/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package certificate

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apierrrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/cluster"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	cmlutils "github.com/gardener/controller-manager-library/pkg/utils"
	dnsapi "github.com/gardener/external-dns-management/pkg/apis/dns/v1alpha1"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/cert/legobridge"
	"github.com/gardener/cert-management/pkg/cert/metrics"
	"github.com/gardener/cert-management/pkg/cert/source"
	"github.com/gardener/cert-management/pkg/cert/utils"
	ctrl "github.com/gardener/cert-management/pkg/controller"
	"github.com/gardener/cert-management/pkg/controller/issuer/core"
)

const (
	// LabelCertificateHashKey is the label for the certificate hash
	LabelCertificateHashKey = api.GroupName + "/certificate-hash"
	// LabelCertificateKey is the label for marking secrets created for a certificate
	LabelCertificateKey = api.GroupName + "/certificate"
	// LabelCertificateBackup is the label for marking backup secrets
	LabelCertificateBackup = api.GroupName + "/backup"
	// LabelCertificateSerialNumber is the label for the certificate serial number
	LabelCertificateSerialNumber = api.GroupName + "/certificate-serialnumber"
	// AnnotationNotAfter is the annotation for storing the not-after timestamp
	AnnotationNotAfter = api.GroupName + "/not-after"
	// AnnotationRevoked is the label for marking revoked secrets
	AnnotationRevoked = api.GroupName + "/revoked"
	// AnnotationRequestedAt is the annotation for storing the timestamp when the certificate was requested
	AnnotationRequestedAt = api.GroupName + "/requestedAt"
)

type backoffMode int

const (
	boNone backoffMode = iota
	boIncrease
	boStop
)

// CertReconciler creates a certReconciler.
func CertReconciler(c controller.Interface, support *core.Support) (reconcile.Interface, error) {
	targetCluster := c.GetCluster(ctrl.TargetCluster)
	certResources, err := targetCluster.Resources().GetByExample(&api.Certificate{})
	if err != nil {
		return nil, err
	}
	certSecretResources, err := targetCluster.Resources().GetByExample(&corev1.Secret{})
	if err != nil {
		return nil, err
	}

	copt, _ := c.GetStringOption(source.OptClass)
	classes := controller.NewClasses(c, copt, source.AnnotClass, source.DefaultClass)

	dnsCluster := c.GetCluster(ctrl.DNSCluster)
	reconciler := &certReconciler{
		support:             support,
		obtainer:            legobridge.NewObtainer(),
		classes:             classes,
		targetCluster:       targetCluster,
		dnsCluster:          dnsCluster,
		certResources:       certResources,
		certSecretResources: certSecretResources,
		rateLimiting:        120 * time.Second,
		pendingRequests:     legobridge.NewPendingRequests(),
		pendingResults:      legobridge.NewPendingResults(),
	}

	dnsNamespace, _ := c.GetStringOption(core.OptDNSNamespace)
	if dnsNamespace != "" {
		reconciler.dnsNamespace = &dnsNamespace
	}
	dnsClass, _ := c.GetStringOption(core.OptDNSClass)
	if dnsClass != "" {
		reconciler.dnsClass = &dnsClass
	}
	dnsOwnerID, _ := c.GetStringOption(core.OptDNSOwnerID)
	if dnsOwnerID != "" {
		reconciler.dnsOwnerID = &dnsOwnerID
	}
	reconciler.cascadeDelete, _ = c.GetBoolOption(core.OptCascadeDelete)

	renewalWindow, err := c.GetDurationOption(core.OptRenewalWindow)
	if err != nil {
		return nil, err
	}
	reconciler.renewalWindow = renewalWindow
	renewalOverdueWindow, err := c.GetDurationOption(core.OptRenewalOverdueWindow)
	if err != nil {
		return nil, err
	}
	reconciler.renewalOverdueWindow = renewalOverdueWindow

	precheckNameservers, _ := c.GetStringOption(core.OptPrecheckNameservers)
	reconciler.precheckNameservers = utils.PreparePrecheckNameservers(strings.Split(precheckNameservers, ","))
	c.Infof("Using these nameservers for DNS propagation checks: %s", strings.Join(reconciler.precheckNameservers, ","))

	reconciler.propagationTimeout, _ = c.GetDurationOption(core.OptPropagationTimeout)
	c.Infof("Propagation timeout: %d seconds", int(reconciler.propagationTimeout.Seconds()))
	reconciler.additionalWait, _ = c.GetDurationOption(core.OptPrecheckAdditionalWait)
	c.Infof("Additional wait time: %d seconds", int(reconciler.additionalWait.Seconds()))

	return reconciler, nil
}

type certReconciler struct {
	reconcile.DefaultReconciler
	support                    *core.Support
	obtainer                   legobridge.Obtainer
	targetCluster              cluster.Interface
	dnsCluster                 cluster.Interface
	certResources              resources.Interface
	certSecretResources        resources.Interface
	rateLimiting               time.Duration
	pendingRequests            *legobridge.PendingCertificateRequests
	pendingResults             *legobridge.PendingResults
	dnsNamespace               *string
	dnsClass                   *string
	dnsOwnerID                 *string
	precheckNameservers        []string
	additionalWait             time.Duration
	propagationTimeout         time.Duration
	renewalWindow              time.Duration
	renewalOverdueWindow       time.Duration
	defaultRequestsPerDayQuota int
	classes                    *controller.Classes
	cascadeDelete              bool
	garbageCollectorTicker     *time.Ticker
}

func (r *certReconciler) Start() {
	r.cleanupOrphanDNSEntriesFromOldChallenges()

	r.cleanupOrphanOutdatedCertificateSecrets()
	r.garbageCollectorTicker = time.NewTicker(7 * 24 * time.Hour)
	go func() {
		for range r.garbageCollectorTicker.C {
			r.cleanupOrphanOutdatedCertificateSecrets()
		}
	}()
}

func (r *certReconciler) Reconcile(logctx logger.LogContext, obj resources.Object) reconcile.Status {
	logctx.Infof("reconciling certificate")
	cert, ok := obj.Data().(*api.Certificate)
	if !ok {
		return r.failedStop(logctx, obj, api.StateError, fmt.Errorf("casting to Certificate failed"))
	}

	if !r.classes.IsResponsibleFor(logctx, obj) {
		logctx.Infof("not responsible")
		return reconcile.Succeeded(logctx)
	}

	if cert.Status.BackOff != nil &&
		obj.GetGeneration() == cert.Status.BackOff.ObservedGeneration &&
		time.Now().Before(cert.Status.BackOff.RetryAfter.Time) {
		interval := cert.Status.BackOff.RetryAfter.Time.Sub(time.Now())
		if interval < 30*time.Second {
			interval = 30 * time.Second
		}
		return reconcile.Recheck(logctx, fmt.Errorf("backoff"), interval)
	}

	oldMsg := cert.Status.Message
	status := r.reconcileCert(logctx, obj, cert)
	newMsg := cert.Status.Message
	changedMsg := !reflect.DeepEqual(newMsg, oldMsg)
	if changedMsg {
		r.addEvent(obj, status, newMsg)
	}
	return status
}

func (r *certReconciler) reconcileCert(logctx logger.LogContext, obj resources.Object, cert *api.Certificate) reconcile.Status {
	r.support.AddCertificate(logctx, cert)

	if r.challengePending(cert) {
		return reconcile.Recheck(logctx, fmt.Errorf("challenge pending for at least one domain of certificate"), 30*time.Second)
	}

	if result := r.pendingResults.Peek(obj.ObjectName()); result != nil {
		status, remove := r.handleObtainOutput(logctx, obj, result)
		if remove {
			r.pendingResults.Remove(obj.ObjectName())
		}
		return status
	}

	secretRef, err := r.determineSecretRef(cert.Namespace, &cert.Spec)
	if err != nil {
		return r.failedStop(logctx, obj, api.StateError, err)
	}

	issuer := r.support.IssuerObjectName(&cert.Spec)
	if r.support.GetIssuerSecretHash(issuer) == "" {
		// issuer not reconciled yet
		logctx.Info("waiting for issuer reconciliation")
		return reconcile.RescheduleAfter(logctx, 5*time.Second)
	}
	var secret *corev1.Secret
	if secretRef != nil {
		secret, err = r.loadSecret(secretRef)
		if err != nil {
			if !apierrrors.IsNotFound(errors.Cause(err)) {
				return r.failed(logctx, obj, api.StateError, err)
			}
			// ignore if SecretRef is specified but not existing
			// will later be used to store the secret
		} else {
			if storedHash := cert.Labels[LabelCertificateHashKey]; storedHash != "" {
				specHash := r.buildSpecHash(&cert.Spec)
				if specHash != storedHash {
					return r.removeStoredHashKeyAndRepeat(logctx, obj)
				}
				return r.checkForRenewAndSucceeded(logctx, obj, secret)
			}

			// corner case: existing secret but no stored hash, check if renewal is overdue
			x509cert, err := legobridge.DecodeCertificateFromSecretData(secret.Data)
			if err == nil && r.isRenewalOverdue(x509cert) {
				r.support.SetCertRenewalOverdue(obj.ObjectName())
			}
		}
	}

	if r.lastPendingRateLimiting(cert.Status.LastPendingTimestamp) {
		remainingSeconds := r.lastPendingRateLimitingSeconds(cert.Status.LastPendingTimestamp)
		return reconcile.Delay(logctx, fmt.Errorf("waiting for end of pending rate limiting in %d seconds", remainingSeconds))
	}
	return r.obtainCertificateAndPending(logctx, obj, nil)
}

func (r *certReconciler) addEvent(obj resources.Object, status reconcile.Status, msg *string) {
	eventType := corev1.EventTypeNormal
	if status.IsFailed() {
		eventType = corev1.EventTypeWarning
	}
	if msg != nil {
		obj.Event(eventType, "reconcile", *msg)
	}
}

func (r *certReconciler) handleObtainOutput(logctx logger.LogContext, obj resources.Object, result *legobridge.ObtainOutput) (reconcile.Status, bool) {
	if result.Err != nil {
		return r.failed(logctx, obj, api.StateError, errors.Wrapf(result.Err, "obtaining certificate failed")), true
	}

	cert, _ := obj.Data().(*api.Certificate)
	specSecretRef, err := r.determineSecretRef(obj.GetNamespace(), &cert.Spec)
	if err != nil {
		return r.failedStop(logctx, obj, api.StateError, err), false
	}

	spec := &api.CertificateSpec{
		CommonName: result.CommonName,
		DNSNames:   result.DNSNames,
		CSR:        result.CSR,
		IssuerRef:  &api.IssuerRef{Name: result.IssuerInfo.Name()},
	}
	specHash := r.buildSpecHash(spec)

	now := time.Now()
	secretRef, err := r.writeCertificateSecret(logctx, result.IssuerInfo, cert.ObjectMeta, result.Certificates, specHash,
		specSecretRef, &now)
	if err != nil {
		return r.failed(logctx, obj, api.StateError, errors.Wrapf(err, "writing certificate secret failed")), false
	}
	logctx.Infof("certificate written in secret %s/%s", secretRef.Namespace, secretRef.Name)

	var notAfter *time.Time
	x509cert, err := legobridge.DecodeCertificate(result.Certificates.Certificate)
	if err == nil {
		notAfter = &x509cert.NotAfter
	}

	status := r.updateSecretRefAndSucceeded(logctx, obj, secretRef, specHash, notAfter)
	return status, status.Error == nil
}

func (r *certReconciler) Deleted(logctx logger.LogContext, key resources.ClusterObjectKey) reconcile.Status {
	r.support.RemoveCertificate(logctx, key.ObjectName())
	logctx.Infof("deleted")

	return reconcile.Succeeded(logctx)
}

func (r *certReconciler) lastPendingRateLimiting(timestamp *metav1.Time) bool {
	endTime := r.rateLimitingEndTime(timestamp)
	return endTime != nil && endTime.After(time.Now())
}

func (r *certReconciler) rateLimitingEndTime(timestamp *metav1.Time) *time.Time {
	if timestamp == nil {
		return nil
	}
	endTime := timestamp.Add(r.rateLimiting).Add(r.additionalWait)
	if r.propagationTimeout > r.rateLimiting/2 {
		endTime = endTime.Add(r.propagationTimeout - r.rateLimiting/2)
	}
	return &endTime
}

func (r *certReconciler) lastPendingRateLimitingSeconds(timestamp *metav1.Time) int {
	endTime := r.rateLimitingEndTime(timestamp)
	if endTime == nil {
		return 0
	}
	seconds := int(endTime.Sub(time.Now()).Seconds() + 0.5)
	if seconds > 0 {
		return seconds
	}
	return 0
}

func (r *certReconciler) challengePending(crt *api.Certificate) bool {
	name := resources.NewObjectName(crt.Namespace, crt.Name)
	return r.pendingRequests.Contains(name)
}

func (r *certReconciler) obtainCertificateAndPending(logctx logger.LogContext, obj resources.Object, renewSecret *corev1.Secret) reconcile.Status {
	cert := obj.Data().(*api.Certificate)
	logctx.Infof("obtain certificate")

	issuer, err := r.support.LoadIssuer(cert)
	if err != nil {
		return r.failed(logctx, obj, api.StateError, err)
	}

	if issuer.Spec.ACME != nil && issuer.Spec.CA != nil {
		return r.failed(logctx, obj, api.StateError, fmt.Errorf("invalid issuer spec: only ACME or CA can be set, but not both"))
	}
	if issuer.Spec.ACME != nil {
		return r.obtainCertificateAndPendingACME(logctx, obj, renewSecret, cert, issuer)
	}
	if issuer.Spec.CA != nil {
		return r.obtainCertificateCA(logctx, obj, renewSecret, cert, issuer)
	}
	return r.failed(logctx, obj, api.StateError, fmt.Errorf("incomplete issuer spec (ACME or CA section must be provided)"))
}

func (r *certReconciler) obtainCertificateAndPendingACME(logctx logger.LogContext, obj resources.Object,
	renewSecret *corev1.Secret, cert *api.Certificate, issuer *api.Issuer) reconcile.Status {
	reguser, err := r.support.RestoreRegUser(issuer)
	if err != nil {
		return r.failed(logctx, obj, api.StateError, err)
	}

	err = r.validateDomainsAndCsr(&cert.Spec, issuer.Spec.ACME.Domains)
	if err != nil {
		return r.failedStop(logctx, obj, api.StateError, err)
	}

	if secretRef, specHash, notAfter := r.findSecretByHashLabel(cert.Namespace, &cert.Spec); secretRef != nil {
		// reuse found certificate
		issuerInfo := utils.NewIssuerInfoFromIssuer(issuer)
		secretRef, err := r.copySecretIfNeeded(logctx, issuerInfo, cert.ObjectMeta, secretRef, specHash, &cert.Spec)
		if err != nil {
			return r.failed(logctx, obj, api.StateError, err)
		}
		return r.updateSecretRefAndSucceeded(logctx, obj, secretRef, specHash, notAfter)
	}

	issuerObjectName := r.support.IssuerObjectName(&cert.Spec)
	if accepted, requestsPerDayQuota := r.support.TryAcceptCertificateRequest(issuerObjectName); !accepted {
		waitMinutes := 1440 / requestsPerDayQuota / 2
		if waitMinutes < 5 {
			waitMinutes = 5
		}
		err := fmt.Errorf("request quota exhausted. Retrying in %d min. "+
			"Up to %d requests per day are allowed. To change the quota, set `spec.requestsPerDayQuota` for issuer %s",
			waitMinutes, requestsPerDayQuota, issuerObjectName)
		return r.recheck(logctx, obj, api.StatePending, err, time.Duration(waitMinutes)*time.Minute)
	}

	var renewCert *certificate.Resource
	if renewSecret != nil {
		renewCert = legobridge.SecretDataToCertificates(renewSecret.Data)
	}

	objectName := obj.ObjectName()
	sublogctx := logctx.NewContext("callback", cert.Name)
	callback := func(output *legobridge.ObtainOutput) {
		r.pendingRequests.Remove(objectName)
		r.pendingResults.Add(objectName, output)
		key := resources.NewClusterKey(r.targetCluster.GetId(), api.Kind(api.CertificateKind), objectName.Namespace(), objectName.Name())
		err := r.support.EnqueueKey(key)
		if err != nil {
			sublogctx.Warnf("Enqueue %s failed with %s", objectName, err.Error())
		}
	}
	var dnsSettings *legobridge.DNSControllerSettings
	if issuer.Spec.ACME.SkipDNSChallengeValidation == nil || !*issuer.Spec.ACME.SkipDNSChallengeValidation {
		dnsSettings = &legobridge.DNSControllerSettings{
			Cluster:             r.dnsCluster,
			Namespace:           cert.Namespace,
			OwnerID:             r.dnsOwnerID,
			PrecheckNameservers: r.precheckNameservers,
			AdditionalWait:      r.additionalWait,
			PropagationTimeout:  r.propagationTimeout,
		}
		if r.dnsNamespace != nil {
			dnsSettings.Namespace = *r.dnsNamespace
		}
	}
	targetDNSClass := ""
	if r.dnsClass != nil {
		targetDNSClass = *r.dnsClass
	}
	input := legobridge.ObtainInput{User: reguser, DNSSettings: dnsSettings, IssuerName: issuerObjectName.Name(),
		CommonName: cert.Spec.CommonName, DNSNames: cert.Spec.DNSNames, CSR: cert.Spec.CSR,
		TargetClass: targetDNSClass, Callback: callback, RequestName: objectName, RenewCert: renewCert}

	err = r.obtainer.Obtain(input)
	if err != nil {
		switch err.(type) {
		case *legobridge.ConcurrentObtainError:
			return r.delay(logctx, obj, api.StatePending, err)
		default:
			return r.failed(logctx, obj, api.StateError, errors.Wrapf(err, "preparing obtaining certificates failed"))
		}
	}
	r.pendingRequests.Add(objectName)
	msg := "certificate requested, preparing/waiting for successful DNS01 challenge"
	return r.pending(logctx, obj, msg)
}

func (r *certReconciler) restoreCA(issuer *api.Issuer) (*legobridge.TLSKeyPair, error) {
	// fetch issuer secret
	secretRef := issuer.Spec.CA.PrivateKeySecretRef
	if secretRef == nil {
		return nil, fmt.Errorf("missing secret ref in issuer")
	}
	if issuer.Status.State != api.StateReady {
		if issuer.Status.State != api.StateError {
			return nil, &core.RecoverableError{Msg: fmt.Sprintf("referenced issuer not ready: state=%s", issuer.Status.State)}
		}
		return nil, fmt.Errorf("referenced issuer not ready: state=%s", issuer.Status.State)
	}
	if issuer.Status.CA == nil || issuer.Status.CA.Raw == nil {
		return nil, fmt.Errorf("CA registration? missing in status")
	}
	issuerSecretObjectName := resources.NewObjectName(secretRef.Namespace, secretRef.Name)
	issuerSecret := &corev1.Secret{}
	_, err := r.support.GetIssuerSecretResources().GetInto(issuerSecretObjectName, issuerSecret)
	if err != nil {
		return nil, errors.Wrap(err, "fetching issuer secret failed")
	}

	CAKeyPair, err := legobridge.CAKeyPairFromSecretData(issuerSecret.Data)
	if err != nil {
		return nil, errors.Wrap(err, "restoring CA issuer from issuer secret failed")
	}

	return CAKeyPair, nil
}

func (r *certReconciler) obtainCertificateCA(logctx logger.LogContext, obj resources.Object,
	renewSecret *corev1.Secret, cert *api.Certificate, issuer *api.Issuer) reconcile.Status {
	CAKeyPair, err := r.restoreCA(issuer)
	if err != nil {
		return r.failed(logctx, obj, api.StateError, err)
	}

	err = r.validateDomainsAndCsr(&cert.Spec, nil)
	if err != nil {
		return r.failedStop(logctx, obj, api.StateError, err)
	}

	if secretRef, specHash, notAfter := r.findSecretByHashLabel(cert.Namespace, &cert.Spec); secretRef != nil {
		// reuse found certificate
		issuerInfo := utils.NewIssuerInfoFromIssuer(issuer)
		secretRef, err := r.copySecretIfNeeded(logctx, issuerInfo, cert.ObjectMeta, secretRef, specHash, &cert.Spec)
		if err != nil {
			return r.failed(logctx, obj, api.StateError, err)
		}
		return r.updateSecretRefAndSucceeded(logctx, obj, secretRef, specHash, notAfter)
	}

	var renewCert *certificate.Resource
	if renewSecret != nil {
		renewCert = legobridge.SecretDataToCertificates(renewSecret.Data)
	}

	objectName := obj.ObjectName()
	sublogctx := logctx.NewContext("callback", cert.Name)
	callback := func(output *legobridge.ObtainOutput) {
		r.pendingRequests.Remove(objectName)
		r.pendingResults.Add(objectName, output)
		key := resources.NewClusterKey(r.targetCluster.GetId(), api.Kind(api.CertificateKind), objectName.Namespace(), objectName.Name())
		err := r.support.EnqueueKey(key)
		if err != nil {
			sublogctx.Warnf("Enqueue %s failed with %s", objectName, err.Error())
		}
	}

	issuerObjectName := r.support.IssuerObjectName(&cert.Spec)
	input := legobridge.ObtainInput{CAKeyPair: CAKeyPair, IssuerName: issuerObjectName.Name(),
		CommonName: cert.Spec.CommonName, DNSNames: cert.Spec.DNSNames, CSR: cert.Spec.CSR,
		Callback: callback, RenewCert: renewCert}

	err = r.obtainer.Obtain(input)
	if err != nil {
		switch err.(type) {
		case *legobridge.ConcurrentObtainError:
			return r.delay(logctx, obj, api.StatePending, err)
		default:
			return r.failed(logctx, obj, api.StateError, errors.Wrap(err, "preparing obtaining certificates failed"))
		}
	}
	r.pendingRequests.Add(objectName)

	msg := "certificate requested, waiting for creation by CA"
	return r.pending(logctx, obj, msg)
}

func (r *certReconciler) validateDomainsAndCsr(spec *api.CertificateSpec, issuerDomains *api.DNSSelection) error {
	var err error
	cn := spec.CommonName
	dnsNames := spec.DNSNames
	if spec.CommonName != nil {
		if spec.CSR != nil {
			return fmt.Errorf("cannot specify both commonName and csr")
		}
		if len(spec.DNSNames) >= 100 {
			return fmt.Errorf("invalid number of DNS names: %d (max 99)", len(spec.DNSNames))
		}
		count := utf8.RuneCount([]byte(*spec.CommonName))
		if count > 64 {
			return fmt.Errorf("the Common Name is limited to 64 characters (X.509 ASN.1 specification), but first given domain %s has %d characters", *spec.CommonName, count)
		}
	} else {
		if spec.CSR == nil {
			return fmt.Errorf("either domains or csr must be specified")
		}
		cn, dnsNames, err = legobridge.ExtractCommonNameAnDNSNames(spec.CSR)
		if err != nil {
			return err
		}
	}

	domainsToValidate := append([]string{*cn}, dnsNames...)
	names := sets.String{}
	for _, name := range domainsToValidate {
		if names.Has(name) {
			return fmt.Errorf("duplicate domain: %s", name)
		}
		names.Insert(name)
	}
	err = r.checkDomainRangeRestriction(issuerDomains, spec, domainsToValidate)
	return err
}

func (r *certReconciler) checkDomainRangeRestriction(issuerDomains *api.DNSSelection, spec *api.CertificateSpec, domains []string) error {
	issuerName := r.support.IssuerName(spec)
	if issuerName == r.support.DefaultIssuerName() && r.support.DefaultIssuerDomainRanges() != nil {
		ranges := r.support.DefaultIssuerDomainRanges()
		for _, domain := range domains {
			if !utils.IsInDomainRanges(domain, ranges) {
				return fmt.Errorf("domain %s is not in domain ranges of default issuer (%s)", domain, strings.Join(ranges, ","))
			}
		}
	}
	if issuerDomains != nil {
		for _, domain := range domains {
			if utils.IsInDomainRanges(domain, issuerDomains.Exclude) {
				return fmt.Errorf("domain %s is an excluded domain of issuer %s (excluded: %s)", domain, issuerName, strings.Join(issuerDomains.Exclude, ","))
			}
			if !utils.IsInDomainRanges(domain, issuerDomains.Include) {
				return fmt.Errorf("domain %s is not an included domain of issuer %s (included: %s)", domain, issuerName, strings.Join(issuerDomains.Include, ","))
			}
		}
	}
	return nil
}

func (r *certReconciler) loadSecret(secretRef *corev1.SecretReference) (*corev1.Secret, error) {
	secretObjectName := resources.NewObjectName(secretRef.Namespace, secretRef.Name)
	secret := &corev1.Secret{}
	_, err := r.certSecretResources.GetInto(secretObjectName, secret)
	if err != nil {
		return nil, errors.Wrap(err, "fetching certificate secret failed")
	}

	return secret, nil
}

func (r *certReconciler) deleteSecret(secretRef *corev1.SecretReference) error {
	if secretRef == nil {
		return nil
	}

	secret := &metav1.ObjectMeta{}
	secret.SetName(secretRef.Name)
	secret.SetNamespace(secretRef.Namespace)
	return r.certSecretResources.DeleteByName(secret)
}

func (r *certReconciler) checkForRenewAndSucceeded(logctx logger.LogContext, obj resources.Object, secret *corev1.Secret) reconcile.Status {
	crt := obj.Data().(*api.Certificate)

	if (crt.Spec.Renew != nil && *crt.Spec.Renew) || crt.Spec.EnsureRenewedAfter != nil {
		status := r.updateForRenewalAndRepeat(logctx, obj)
		if status != nil {
			return *status
		}
	}

	cert, err := legobridge.DecodeCertificateFromSecretData(secret.Data)
	if err != nil {
		logctx.Errorf("certificate secret cannot be decoded: %s", err)
	}

	revoked := false
	if _, ok := resources.GetAnnotation(secret, AnnotationRevoked); ok {
		revoked = true
	}
	if revoked {
		r.support.SetCertRevoked(obj.ObjectName())
	} else if cert != nil && r.isRenewalOverdue(cert) {
		r.support.SetCertRenewalOverdue(obj.ObjectName())
	} else {
		r.support.ClearCertRevoked(obj.ObjectName())
		r.support.ClearCertRenewalOverdue(obj.ObjectName())
	}
	requestedAt := ExtractRequestedAtFromAnnotation(secret)
	if cert == nil || r.explictRenewalRequested(cert, requestedAt, crt.Spec.EnsureRenewedAfter) || !revoked && r.needsRenewal(cert) {
		if crt.Status.State == api.StatePending && r.lastPendingRateLimiting(crt.Status.LastPendingTimestamp) {
			return reconcile.Succeeded(logctx)
		}

		logctx.Infof("start obtaining certificate")
		return r.obtainCertificateAndPending(logctx, obj, secret)
	}
	if revoked {
		return r.revoked(logctx, obj)
	}

	msg := fmt.Sprintf("certificate (SN %s) valid from %v to %v", SerialNumberToString(cert.SerialNumber, false), cert.NotBefore, cert.NotAfter)
	logctx.Infof(msg)
	return r.succeeded(logctx, obj, &msg)
}

func (r *certReconciler) updateForRenewalAndRepeat(logctx logger.LogContext, obj resources.Object) *reconcile.Status {
	crt := obj.Data().(*api.Certificate)

	now := &metav1.Time{Time: time.Now()}
	var renewalTime *metav1.Time
	if crt.Spec.EnsureRenewedAfter != nil && crt.Spec.EnsureRenewedAfter.Before(now) {
		renewalTime = crt.Spec.EnsureRenewedAfter
	} else {
		renewalTime = now
	}
	if crt.Spec.Renew != nil || !reflect.DeepEqual(crt.Spec.EnsureRenewedAfter, renewalTime) {
		logctx.Infof("Ensure renewal after %s", renewalTime)
		crt.Spec.Renew = nil
		crt.Spec.EnsureRenewedAfter = renewalTime
		err := obj.Update()
		if err != nil {
			status := r.failed(logctx, obj, crt.Status.State, errors.Wrap(err, "requesting renewal"))
			return &status
		}
		status := reconcile.RescheduleAfter(logctx, 1*time.Second)
		return &status
	}
	return nil
}

func (r *certReconciler) buildSpecHash(spec *api.CertificateSpec) string {
	h := sha256.New224()
	if spec.CommonName != nil {
		h.Write([]byte(*spec.CommonName))
		h.Write([]byte{0})
		for _, domain := range spec.DNSNames {
			h.Write([]byte(domain))
			h.Write([]byte{0})
		}
	}
	if spec.CSR != nil {
		h.Write([]byte{0})
		h.Write(spec.CSR)
		h.Write([]byte{0})
	}
	issuer := r.support.IssuerObjectName(spec)
	hash := r.support.GetIssuerSecretHash(issuer)
	h.Write([]byte(hash))
	h.Write([]byte{0})
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (r *certReconciler) explictRenewalRequested(cert *x509.Certificate, requestedAt *time.Time, ensureRenewalAfter *metav1.Time) bool {
	return ensureRenewalAfter != nil && WasRequestedBefore(cert, requestedAt, ensureRenewalAfter.Time)
}

func (r *certReconciler) needsRenewal(cert *x509.Certificate) bool {
	return cert.NotAfter.Before(time.Now().Add(r.renewalWindow))
}

func (r *certReconciler) isRenewalOverdue(cert *x509.Certificate) bool {
	return cert.NotAfter.Before(time.Now().Add(r.renewalOverdueWindow))
}

func (r *certReconciler) determineSecretRef(namespace string, spec *api.CertificateSpec) (*corev1.SecretReference, error) {
	ns := core.NormalizeNamespace(namespace)
	if spec.SecretRef != nil {
		if spec.SecretRef.Namespace != "" && spec.SecretRef.Namespace != ns {
			return nil, fmt.Errorf("secretRef must be located in same namespace as certificate for security reasons")
		}
		if spec.SecretRef.Name == "" {
			return nil, fmt.Errorf("secretRef.name must not be empty if specified")
		}
		if spec.SecretName != nil && *spec.SecretName != spec.SecretRef.Name {
			return nil, fmt.Errorf("conflicting names in secretRef.Name and secretName: %s != %s", spec.SecretRef.Name, *spec.SecretName)
		}
		return &corev1.SecretReference{
			Name:      spec.SecretRef.Name,
			Namespace: ns,
		}, nil
	} else if spec.SecretName != nil && *spec.SecretName != "" {
		return &corev1.SecretReference{
			Name:      *spec.SecretName,
			Namespace: ns,
		}, nil
	}

	// secret reference name will be generated
	return nil, nil
}

func (r *certReconciler) findSecretByHashLabel(namespace string, spec *api.CertificateSpec) (*corev1.SecretReference, string, *time.Time) {
	specHash := r.buildSpecHash(spec)
	objs, err := FindAllCertificateSecretsByHashLabel(r.certSecretResources, specHash)
	if err != nil {
		return nil, "", nil
	}

	secretRef, _ := r.determineSecretRef(namespace, spec)
	var best resources.Object
	var bestNotAfter time.Time
	for _, obj := range objs {
		if obj.GetAnnotation(AnnotationRevoked) != "" {
			continue
		}
		secret := obj.Data().(*corev1.Secret)
		cert, err := legobridge.DecodeCertificateFromSecretData(secret.Data)
		if err != nil {
			continue
		}

		requestedAt := ExtractRequestedAtFromAnnotation(secret)
		if !r.needsRenewal(cert) && !r.explictRenewalRequested(cert, requestedAt, spec.EnsureRenewedAfter) {
			if best == nil ||
				bestNotAfter.Before(cert.NotAfter) ||
				secretRef != nil && bestNotAfter.Equal(cert.NotAfter) && obj.GetName() == secretRef.Name && core.NormalizeNamespace(obj.GetNamespace()) == core.NormalizeNamespace(secretRef.Namespace) {

				best = obj
				bestNotAfter = cert.NotAfter
			}
		}
	}
	if best == nil {
		return nil, "", nil
	}
	ref := &corev1.SecretReference{Namespace: best.GetNamespace(), Name: best.GetName()}
	return ref, specHash, &bestNotAfter
}

func (r *certReconciler) copySecretIfNeeded(logctx logger.LogContext, issuerInfo utils.IssuerInfo,
	objectMeta metav1.ObjectMeta, secretRef *corev1.SecretReference, specHash string, spec *api.CertificateSpec) (*corev1.SecretReference, error) {
	ns := core.NormalizeNamespace(objectMeta.Namespace)
	specSecretRef, _ := r.determineSecretRef(ns, spec)
	if specSecretRef != nil && secretRef.Name == specSecretRef.Name &&
		(secretRef.Namespace == "" || secretRef.Namespace == ns) {
		return specSecretRef, nil
	}
	secret, err := r.loadSecret(secretRef)
	if err != nil {
		return nil, err
	}
	certificates := legobridge.SecretDataToCertificates(secret.Data)

	var requestedAt *time.Time = ExtractRequestedAtFromAnnotation(secret)

	return r.writeCertificateSecret(logctx, issuerInfo, objectMeta, certificates, specHash, specSecretRef, requestedAt)
}

func (r *certReconciler) writeCertificateSecret(logctx logger.LogContext, issuerInfo utils.IssuerInfo, objectMeta metav1.ObjectMeta,
	certificates *certificate.Resource, specHash string, specSecretRef *corev1.SecretReference, requestedAt *time.Time) (*corev1.SecretReference, error) {
	secret := &corev1.Secret{
		Type: corev1.SecretTypeTLS,
	}
	secret.SetNamespace(core.NormalizeNamespace(objectMeta.GetNamespace()))
	if specSecretRef != nil {
		secret.SetName(specSecretRef.Name)
		// reuse existing secret (especially keep existing annotations and labels)
		obj, err := r.certSecretResources.GetInto1(secret)
		if err == nil {
			secret = obj.Data().(*corev1.Secret)
		}
	} else {
		secret.SetGenerateName(objectMeta.GetName() + "-")
	}
	resources.SetLabel(secret, LabelCertificateHashKey, specHash)
	resources.SetLabel(secret, LabelCertificateKey, "true")
	resources.RemoveAnnotation(secret, AnnotationRevoked)
	setRequestedAtAnnotation(secret, requestedAt)
	secret.Data = legobridge.CertificatesToSecretData(certificates)
	if r.cascadeDelete {
		ownerReferences := []metav1.OwnerReference{{APIVersion: api.Version, Kind: api.CertificateKind, Name: objectMeta.GetName(), UID: objectMeta.GetUID()}}
		if objectMeta.GetAnnotations() != nil && objectMeta.GetAnnotations()[source.AnnotForwardOwnerRefs] == "true" {
			if objectMeta.OwnerReferences != nil {
				ownerReferences = append(ownerReferences, objectMeta.OwnerReferences...)
			}
		}
		secret.SetOwnerReferences(ownerReferences)
	}

	obj, err := r.certSecretResources.CreateOrUpdate(secret)
	if err != nil {
		return nil, errors.Wrap(err, "creating/updating certificate secret failed")
	}

	ref, created, err := BackupSecret(r.certSecretResources, secret, specHash, issuerInfo)
	if err != nil {
		logctx.Warnf("Backup of secret %s/%s failed: %s", secret.Namespace, secret.Name, err)
	} else if created {
		logctx.Infof("Created backup secret %s/%s", ref.Namespace, ref.Name)
	}

	return &corev1.SecretReference{Name: obj.GetName(), Namespace: obj.GetNamespace()}, nil
}

func (r *certReconciler) updateSecretRefAndSucceeded(logctx logger.LogContext, obj resources.Object,
	secretRef *corev1.SecretReference, specHash string, notAfter *time.Time) reconcile.Status {
	crt := obj.Data().(*api.Certificate)
	crt.Spec.SecretRef = secretRef
	if crt.Labels == nil {
		crt.Labels = map[string]string{}
	}
	crt.Labels[LabelCertificateHashKey] = specHash
	if notAfter != nil {
		resources.SetAnnotation(crt, AnnotationNotAfter, notAfter.Format(time.RFC3339))
	} else {
		resources.RemoveAnnotation(crt, AnnotationNotAfter)
	}
	obj2, err := r.certResources.Update(crt)
	if err != nil {
		return r.failed(logctx, obj, api.StateError, errors.Wrap(err, "updating certificate resource failed"))
	}
	return r.succeeded(logctx, obj2, nil)
}

func (r *certReconciler) removeStoredHashKeyAndRepeat(logctx logger.LogContext, obj resources.Object) reconcile.Status {
	c := obj.Data().(*api.Certificate)
	delete(c.Labels, LabelCertificateHashKey)
	obj2, err := r.certResources.Update(c)
	if err != nil {
		return r.failed(logctx, obj, api.StateError, errors.Wrap(err, "updating certificate resource failed"))
	}
	return r.repeat(logctx, obj2)
}

func (r *certReconciler) prepareUpdateStatus(obj resources.Object, state string, msg *string, mode backoffMode) (*resources.ModificationState, *api.CertificateStatus) {
	crt := obj.Data().(*api.Certificate)
	status := &crt.Status

	mod := resources.NewModificationState(obj)
	mod.AssureStringPtrPtr(&status.Message, msg)
	mod.AssureStringValue(&status.State, state)
	mod.AssureInt64Value(&status.ObservedGeneration, obj.GetGeneration())
	switch state {
	case api.StateReady:
		mod.Modify(status.BackOff != nil)
		status.BackOff = nil
		mod.Modify(status.LastPendingTimestamp != nil)
		status.LastPendingTimestamp = nil
	case api.StatePending:
		// nothing to do
	default:
		if mode != boNone {
			interval := r.rateLimiting
			if status.BackOff != nil && status.ObservedGeneration == status.BackOff.ObservedGeneration {
				interval += status.BackOff.RetryInterval.Duration
				if interval > 8*time.Hour {
					interval = 8 * time.Hour
				}
			}
			if mode == boStop {
				interval = 24 * time.Hour
			}
			status.BackOff = &api.BackOffState{
				ObservedGeneration: status.ObservedGeneration,
				RetryAfter:         metav1.Time{Time: time.Now().Add(interval)},
				RetryInterval:      metav1.Duration{Duration: interval},
			}
			mod.Modify(true)
		}
	}

	cn := crt.Spec.CommonName
	dnsNames := crt.Spec.DNSNames
	if crt.Spec.CSR != nil {
		cn, dnsNames, _ = legobridge.ExtractCommonNameAnDNSNames(crt.Spec.CSR)
	}
	mod.AssureStringPtrPtr(&status.CommonName, cn)
	utils.AssureStringArray(mod.ModificationState, &status.DNSNames, dnsNames)

	var expirationDate *string
	notAfter, ok := resources.GetAnnotation(crt, AnnotationNotAfter)
	if ok {
		expirationDate = &notAfter
	}
	mod.AssureStringPtrPtr(&status.ExpirationDate, expirationDate)

	issuerRef := crt.Spec.IssuerRef
	if issuerRef == nil {
		issuerRef = &api.IssuerRef{Name: r.support.DefaultIssuerName()}
	}
	if status.IssuerRef == nil || status.IssuerRef.Name != issuerRef.Name || status.IssuerRef.Namespace != r.support.IssuerNamespace() {
		status.IssuerRef = &api.IssuerRefWithNamespace{Name: issuerRef.Name, Namespace: r.support.IssuerNamespace()}
		mod.Modify(true)
	}

	return mod, status
}

func (r *certReconciler) updateStatus(logctx logger.LogContext, mod *resources.ModificationState) {
	err := mod.UpdateStatus()
	if err != nil {
		logctx.Warnf("updating status failed with: %s", err)
	}
}

func (r *certReconciler) failed(logctx logger.LogContext, obj resources.Object, state string, err error) reconcile.Status {
	return r.status(logctx, obj, state, err, false)
}

func (r *certReconciler) failedStop(logctx logger.LogContext, obj resources.Object, state string, err error) reconcile.Status {
	return r.status(logctx, obj, state, err, true)
}

func (r *certReconciler) status(logctx logger.LogContext, obj resources.Object, state string, err error, stop bool) reconcile.Status {
	msg := err.Error()

	rerr, isRecoverable := err.(*core.RecoverableError)
	backoffMode := boNone
	if !isRecoverable {
		if stop {
			backoffMode = boStop
		} else {
			backoffMode = boIncrease
		}
	}
	mod, _ := r.prepareUpdateStatus(obj, state, &msg, backoffMode)
	r.updateStatus(logctx, mod)

	if isRecoverable {
		if rerr.Interval != 0 {
			return reconcile.Recheck(logctx, err, rerr.Interval)
		}
		return reconcile.Delay(logctx, err)
	}
	return reconcile.Failed(logctx, err)
}

func (r *certReconciler) delay(logctx logger.LogContext, obj resources.Object, state string, err error) reconcile.Status {
	return r.status(logctx, obj, state, &core.RecoverableError{Msg: err.Error()}, false)
}

func (r *certReconciler) recheck(logctx logger.LogContext, obj resources.Object, state string, err error, interval time.Duration) reconcile.Status {
	return r.status(logctx, obj, state, &core.RecoverableError{Msg: err.Error(), Interval: interval}, false)
}

func (r *certReconciler) succeeded(logctx logger.LogContext, obj resources.Object, msg *string) reconcile.Status {
	mod, _ := r.prepareUpdateStatus(obj, api.StateReady, msg, boNone)
	r.updateStatus(logctx, mod)

	return reconcile.Succeeded(logctx)
}

func (r *certReconciler) revoked(logctx logger.LogContext, obj resources.Object) reconcile.Status {
	msg := "certificate has been revoked"
	mod, _ := r.prepareUpdateStatus(obj, api.StateRevoked, &msg, boNone)
	r.updateStatus(logctx, mod)

	return reconcile.Succeeded(logctx)
}

func (r *certReconciler) pending(logctx logger.LogContext, obj resources.Object, msg string) reconcile.Status {
	mod, status := r.prepareUpdateStatus(obj, api.StatePending, &msg, boNone)
	status.LastPendingTimestamp = &metav1.Time{Time: time.Now()}
	mod.Modified = true
	r.updateStatus(logctx, mod)

	return reconcile.Succeeded(logctx)
}

func (r *certReconciler) repeat(logctx logger.LogContext, obj resources.Object) reconcile.Status {
	mod, _ := r.prepareUpdateStatus(obj, "", nil, boNone)
	r.updateStatus(logctx, mod)

	return reconcile.Repeat(logctx)
}

func (r *certReconciler) cleanupOrphanDNSEntriesFromOldChallenges() {
	// find orphan dnsentries from DNSChallenges and try to delete them
	// should only happen if cert-manager is terminated during running DNS challenge(s)

	entriesResource, err := r.dnsCluster.Resources().GetByExample(&dnsapi.DNSEntry{})
	if err != nil {
		logger.Warnf("issuer: cleanupOrphanDNSEntriesFromOldChallenges failed with: %s", err)
		return
	}
	var objects []resources.Object
	if r.dnsNamespace != nil {
		objects, err = entriesResource.Namespace(*r.dnsNamespace).List(metav1.ListOptions{})
	} else {
		objects, err = entriesResource.List(metav1.ListOptions{})
	}
	if err != nil {
		logger.Warnf("issuer: cleanupOrphanDNSEntriesFromOldChallenges failed with: %s", err)
		return
	}
	count := 0
	for _, obj := range objects {
		class, ok := resources.GetAnnotation(obj.Data(), source.AnnotClass)
		if ok && r.classes.Contains(class) {
			err = entriesResource.Delete(obj.Data())
			if err != nil {
				logger.Warnf("issuer: deleting DNS entry %s/%s failed with: %s", obj.GetNamespace(), obj.GetName(), err)
			} else {
				count++
			}
		}
	}
	logger.Infof("issuer: cleanup: %d orphan DNS entries deleted", count)
}

// cleanupOrphanOutdatedCertificateSecrets performs a garbage collection of orphan secrets.
// A certificate secret is deleted if it is not referenced by a certificate custom resource and
// if its TLS certificate is not valid since at least 14 days.
func (r *certReconciler) cleanupOrphanOutdatedCertificateSecrets() {
	const prefix = "issuer: cleanup-secrets: "
	logger.Infof(prefix + "starting GC for orphan outdated certificate secrets")
	deleted := 0
	outdated := 0
	backup := 0
	revoked := 0
	// only select secrets with label `cert.gardener.cloud/certificate=true`
	opts := metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=true", LabelCertificateKey),
	}
	secrets, err := r.certSecretResources.List(opts)
	if err != nil {
		logger.Warnf(prefix+"list secrets failed with %s", err)
		return
	}
	certs, err := r.certResources.List(metav1.ListOptions{})
	if err != nil {
		logger.Warnf(prefix+"list certificates failed with %s", err)
		return
	}
	secretNamesToKeep := cmlutils.StringSet{}
	for _, obj := range certs {
		cert := obj.Data().(*api.Certificate)
		ref := cert.Spec.SecretRef
		if ref != nil {
			secretNamesToKeep.Add(ref.Namespace + "/" + ref.Name)
		}
	}
	for _, obj := range secrets {
		secret := obj.Data().(*corev1.Secret)
		key := secret.Namespace + "/" + secret.Name
		if value, ok := resources.GetLabel(secret, LabelCertificateBackup); ok && value == "true" {
			backup++
		}
		if value, ok := resources.GetAnnotation(secret, AnnotationRevoked); ok && value == "true" {
			revoked++
		}
		if secretNamesToKeep.Contains(key) {
			continue
		}
		cert, err := legobridge.DecodeCertificateFromSecretData(secret.Data)
		if err != nil {
			logger.Warnf(prefix+"cannot decode certificate for secret %s: %s", key, err)
			continue
		}
		if cert.NotAfter.Add(14 * 24 * time.Hour).After(time.Now()) {
			continue
		}
		outdated++
		err = r.certSecretResources.Delete(secret)
		if err != nil {
			logger.Warnf(prefix+"cannot delete certificate secret %s: %s", key, err)
			continue
		}
		deleted++
	}

	metrics.ReportCertificateSecrets("total", len(secrets))
	metrics.ReportCertificateSecrets("backup", backup)
	metrics.ReportCertificateSecrets("revoked", revoked)

	logger.Infof("issuer: cleanup-secrets: %d/%d orphan outdated certificate secrets deleted (%d total, %d backups, %d revoked)",
		deleted, outdated, len(secrets), backup, revoked)
}

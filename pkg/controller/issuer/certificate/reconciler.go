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
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-acme/lego/v3/certificate"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apierrrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/cluster"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	dnsapi "github.com/gardener/external-dns-management/pkg/apis/dns/v1alpha1"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/cert/legobridge"
	"github.com/gardener/cert-management/pkg/cert/source"
	"github.com/gardener/cert-management/pkg/cert/utils"
	ctrl "github.com/gardener/cert-management/pkg/controller"
	"github.com/gardener/cert-management/pkg/controller/issuer/core"
)

const (
	// LabelCertificateHashKey is the label for the certificate hash
	LabelCertificateHashKey = api.GroupName + "/certificate-hash"
	// LabelCertificateKey is the label for the certificate
	LabelCertificateKey = api.GroupName + "/certificate"
	// AnnotationNotAfter is the annotation for storing the not-after timestamp
	AnnotationNotAfter = api.GroupName + "/not-after"
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

	precheckNameservers, _ := c.GetStringOption(core.OptPrecheckNameservers)
	reconciler.precheckNameservers = utils.PreparePrecheckNameservers(strings.Split(precheckNameservers, ","))
	c.Infof("Using these nameservers for DNS propagation checks: %s", strings.Join(reconciler.precheckNameservers, ","))

	reconciler.propagationTimeout, _ = c.GetDurationOption(core.OptPropagationTimeout)
	c.Infof("Propagation timeout: %d seconds", int(reconciler.propagationTimeout.Seconds()))
	reconciler.additionalWait, _ = c.GetDurationOption(core.OptPrecheckAdditionalWait)
	c.Infof("Additional wait time: %d seconds", int(reconciler.additionalWait.Seconds()))

	return reconciler, nil
}

type recoverableError struct {
	Msg      string
	Interval time.Duration
}

func (err *recoverableError) Error() string {
	return err.Msg
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
	renewalCheckPeriod         time.Duration
	defaultRequestsPerDayQuota int
	classes                    *controller.Classes
	cascadeDelete              bool
}

func (r *certReconciler) Start() {
	r.cleanupOrphanDNSEntriesFromOldChallenges()
}

func (r *certReconciler) Reconcile(logger logger.LogContext, obj resources.Object) reconcile.Status {
	logger.Infof("reconciling certificate")
	cert, ok := obj.Data().(*api.Certificate)
	if !ok {
		return r.failedStop(logger, obj, api.StateError, fmt.Errorf("casting to Certificate failed"))
	}

	if !r.classes.IsResponsibleFor(logger, obj) {
		logger.Infof("not responsible")
		return reconcile.Succeeded(logger)
	}

	if cert.Status.BackOff != nil &&
		obj.GetGeneration() == cert.Status.BackOff.ObservedGeneration &&
		time.Now().Before(cert.Status.BackOff.RetryAfter.Time) {
		interval := cert.Status.BackOff.RetryAfter.Time.Sub(time.Now())
		if interval < 30*time.Second {
			interval = 30 * time.Second
		}
		return reconcile.Recheck(logger, fmt.Errorf("backoff"), interval)
	}

	r.support.AddCertificate(logger, cert)

	if r.challengePending(cert) {
		return reconcile.Recheck(logger, fmt.Errorf("challenge pending for at least one domain of certificate"), 30*time.Second)
	}

	if result := r.pendingResults.Peek(obj.ObjectName()); result != nil {
		status, remove := r.handleObtainOutput(logger, obj, result)
		if remove {
			r.pendingResults.Remove(obj.ObjectName())
		}
		return status
	}

	secretRef, err := r.determineSecretRef(cert.Namespace, &cert.Spec)
	if err != nil {
		return r.failedStop(logger, obj, api.StateError, err)
	}
	var secret *corev1.Secret
	if secretRef != nil {
		secret, err = r.loadSecret(secretRef)
		if err != nil {
			if !apierrrors.IsNotFound(errors.Cause(err)) {
				return r.failed(logger, obj, api.StateError, err)
			}
			// ignore if SecretRef is specified but not existing
			// will later be used to store the secret
		} else if storedHash := cert.Labels[LabelCertificateHashKey]; storedHash != "" {
			specHash := r.buildSpecHash(&cert.Spec)
			if specHash != storedHash {
				return r.removeStoredHashKeyAndRepeat(logger, obj)
			}
			return r.checkForRenewAndSucceeded(logger, obj, secret)
		}
	}

	if r.lastPendingRateLimiting(cert.Status.LastPendingTimestamp) {
		remainingSeconds := r.lastPendingRateLimitingSeconds(cert.Status.LastPendingTimestamp)
		return reconcile.Delay(logger, fmt.Errorf("waiting for end of pending rate limiting in %d seconds", remainingSeconds))
	}
	return r.obtainCertificateAndPending(logger, obj, nil)
}

func (r *certReconciler) handleObtainOutput(logger logger.LogContext, obj resources.Object, result *legobridge.ObtainOutput) (reconcile.Status, bool) {
	if result.Err != nil {
		return r.failed(logger, obj, api.StateError, errors.Wrapf(result.Err, "obtaining certificate failed")), true
	}

	cert, _ := obj.Data().(*api.Certificate)
	specSecretRef, err := r.determineSecretRef(obj.GetNamespace(), &cert.Spec)
	if err != nil {
		return r.failedStop(logger, obj, api.StateError, err), false
	}

	spec := &api.CertificateSpec{
		CommonName: result.CommonName,
		DNSNames:   result.DNSNames,
		CSR:        result.CSR,
		IssuerRef:  &api.IssuerRef{Name: result.IssuerName},
	}
	specHash := r.buildSpecHash(spec)

	secretRef, err := r.writeCertificateSecret(cert.ObjectMeta, result.Certificates, specHash, specSecretRef)
	if err != nil {
		return r.failed(logger, obj, api.StateError, errors.Wrapf(err, "writing certificate secret failed")), false
	}
	logger.Infof("certificate written in secret %s/%s", secretRef.Namespace, secretRef.Name)

	var notAfter *time.Time
	x509cert, err := legobridge.DecodeCertificate(result.Certificates.Certificate)
	if err == nil {
		notAfter = &x509cert.NotAfter
	}

	status := r.updateSecretRefAndSucceeded(logger, obj, secretRef, specHash, notAfter)
	return status, status.Error == nil
}

func (r *certReconciler) Deleted(logger logger.LogContext, key resources.ClusterObjectKey) reconcile.Status {
	r.support.RemoveCertificate(logger, key.ObjectName())
	logger.Infof("deleted")

	return reconcile.Succeeded(logger)
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

func (r *certReconciler) obtainCertificateAndPending(logger logger.LogContext, obj resources.Object, renewSecret *corev1.Secret) reconcile.Status {
	cert := obj.Data().(*api.Certificate)
	logger.Infof("obtain certificate")

	issuer, err := r.loadIssuer(cert)
	if err != nil {
		return r.failed(logger, obj, api.StateError, err)
	}

	if issuer.Spec.ACME != nil && issuer.Spec.CA != nil {
		return r.failed(logger, obj, api.StateError, fmt.Errorf("invalid issuer spec: only ACME or CA can be set, but not both"))
	}
	if issuer.Spec.ACME != nil {
		return r.obtainCertificateAndPendingACME(logger, obj, renewSecret, cert, issuer)
	}
	if issuer.Spec.CA != nil {
		return r.obtainCertificateCA(logger, obj, renewSecret, cert, issuer)
	}
	return r.failed(logger, obj, api.StateError, fmt.Errorf("incomplete issuer spec (ACME or CA section must be provided)"))
}

func (r *certReconciler) obtainCertificateAndPendingACME(logger logger.LogContext, obj resources.Object,
	renewSecret *corev1.Secret, cert *api.Certificate, issuer *api.Issuer) reconcile.Status {
	reguser, server, err := r.restoreRegUser(issuer)
	if err != nil {
		return r.failed(logger, obj, api.StateError, err)
	}

	err = r.validateDomainsAndCsr(&cert.Spec)
	if err != nil {
		return r.failedStop(logger, obj, api.StateError, err)
	}

	if secretRef, specHash, notAfter := r.findSecretByHashLabel(cert.Namespace, &cert.Spec); secretRef != nil {
		// reuse found certificate
		secretRef, err := r.copySecretIfNeeded(cert.ObjectMeta, secretRef, specHash, &cert.Spec)
		if err != nil {
			return r.failed(logger, obj, api.StateError, err)
		}
		return r.updateSecretRefAndSucceeded(logger, obj, secretRef, specHash, notAfter)
	}

	issuerObjectName := r.issuerObjectName(&cert.Spec)
	if accepted, requestsPerDayQuota := r.support.TryAcceptCertificateRequest(issuerObjectName); !accepted {
		waitMinutes := 1440 / requestsPerDayQuota / 2
		if waitMinutes < 5 {
			waitMinutes = 5
		}
		err := fmt.Errorf("request quota exhausted. Retrying in %d min. "+
			"Up to %d requests per day are allowed. To change the quota, set `spec.requestsPerDayQuota` for issuer %s",
			waitMinutes, requestsPerDayQuota, issuerObjectName)
		return r.recheck(logger, obj, api.StatePending, err, time.Duration(waitMinutes)*time.Minute)
	}

	var renewCert *certificate.Resource
	if renewSecret != nil {
		renewCert = legobridge.SecretDataToCertificates(renewSecret.Data)
	}

	objectName := obj.ObjectName()
	subLogger := logger.NewContext("callback", cert.Name)
	callback := func(output *legobridge.ObtainOutput) {
		r.pendingRequests.Remove(objectName)
		r.pendingResults.Add(objectName, output)
		key := resources.NewClusterKey(r.targetCluster.GetId(), api.Kind(api.CertificateKind), objectName.Namespace(), objectName.Name())
		err := r.support.EnqueueKey(key)
		if err != nil {
			subLogger.Warnf("Enqueue %s failed with %s", objectName, err.Error())
		}
	}
	dnsSettings := legobridge.DNSControllerSettings{
		Namespace:           cert.Namespace,
		OwnerID:             r.dnsOwnerID,
		PrecheckNameservers: r.precheckNameservers,
		AdditionalWait:      r.additionalWait,
		PropagationTimeout:  r.propagationTimeout,
	}
	if r.dnsNamespace != nil {
		dnsSettings.Namespace = *r.dnsNamespace
	}
	targetDNSClass := ""
	if r.dnsClass != nil {
		targetDNSClass = *r.dnsClass
	}
	input := legobridge.ObtainInput{User: reguser, DNSCluster: r.dnsCluster, DNSSettings: dnsSettings,
		CaDirURL: server, IssuerName: issuerObjectName.Name(),
		CommonName: cert.Spec.CommonName, DNSNames: cert.Spec.DNSNames, CSR: cert.Spec.CSR,
		TargetClass: targetDNSClass, Callback: callback, RequestName: objectName, RenewCert: renewCert}

	err = r.obtainer.Obtain(input)
	if err != nil {
		switch err.(type) {
		case *legobridge.ConcurrentObtainError:
			return r.delay(logger, obj, api.StatePending, err)
		default:
			return r.failed(logger, obj, api.StateError, errors.Wrapf(err, "preparing obtaining certificates failed"))
		}
	}
	r.pendingRequests.Add(objectName)
	msg := "certificate requested, preparing/waiting for successful DNS01 challenge"
	return r.pending(logger, obj, msg)
}

func (r *certReconciler) restoreCA(issuer *api.Issuer) (*legobridge.TLSKeyPair, error) {
	// fetch issuer secret
	secretRef := issuer.Spec.CA.PrivateKeySecretRef
	if secretRef == nil {
		return nil, fmt.Errorf("missing secret ref in issuer")
	}
	if issuer.Status.State != api.StateReady {
		if issuer.Status.State != api.StateError {
			return nil, &recoverableError{Msg: fmt.Sprintf("referenced issuer not ready: state=%s", issuer.Status.State)}
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

func (r *certReconciler) obtainCertificateCA(logger logger.LogContext, obj resources.Object,
	renewSecret *corev1.Secret, cert *api.Certificate, issuer *api.Issuer) reconcile.Status {
	CAKeyPair, err := r.restoreCA(issuer)
	if err != nil {
		return r.failed(logger, obj, api.StateError, err)
	}

	err = r.validateDomainsAndCsr(&cert.Spec)
	if err != nil {
		return r.failedStop(logger, obj, api.StateError, err)
	}

	if secretRef, specHash, notAfter := r.findSecretByHashLabel(cert.Namespace, &cert.Spec); secretRef != nil {
		// reuse found certificate
		secretRef, err := r.copySecretIfNeeded(cert.ObjectMeta, secretRef, specHash, &cert.Spec)
		if err != nil {
			return r.failed(logger, obj, api.StateError, err)
		}
		return r.updateSecretRefAndSucceeded(logger, obj, secretRef, specHash, notAfter)
	}

	var renewCert *certificate.Resource
	if renewSecret != nil {
		renewCert = legobridge.SecretDataToCertificates(renewSecret.Data)
	}

	objectName := obj.ObjectName()
	subLogger := logger.NewContext("callback", cert.Name)
	callback := func(output *legobridge.ObtainOutput) {
		r.pendingRequests.Remove(objectName)
		r.pendingResults.Add(objectName, output)
		key := resources.NewClusterKey(r.targetCluster.GetId(), api.Kind(api.CertificateKind), objectName.Namespace(), objectName.Name())
		err := r.support.EnqueueKey(key)
		if err != nil {
			subLogger.Warnf("Enqueue %s failed with %s", objectName, err.Error())
		}
	}

	issuerObjectName := r.issuerObjectName(&cert.Spec)
	input := legobridge.ObtainInput{CAKeyPair: CAKeyPair, IssuerName: issuerObjectName.Name(),
		CommonName: cert.Spec.CommonName, DNSNames: cert.Spec.DNSNames, CSR: cert.Spec.CSR,
		Callback: callback, RenewCert: renewCert}

	err = r.obtainer.Obtain(input)
	if err != nil {
		switch err.(type) {
		case *legobridge.ConcurrentObtainError:
			return r.delay(logger, obj, api.StatePending, err)
		default:
			return r.failed(logger, obj, api.StateError, errors.Wrap(err, "preparing obtaining certificates failed"))
		}
	}
	r.pendingRequests.Add(objectName)

	msg := "certificate requested, waiting for creation by CA"
	return r.pending(logger, obj, msg)
}

func (r *certReconciler) loadIssuer(crt *api.Certificate) (*api.Issuer, error) {
	// fetch issuer
	issuerObjectName := r.issuerObjectName(&crt.Spec)
	issuer := &api.Issuer{}
	_, err := r.support.GetIssuerResources().GetInto(issuerObjectName, issuer)
	if err != nil {
		return nil, errors.Wrap(err, "fetching issuer failed")
	}
	return issuer, nil
}

func (r *certReconciler) restoreRegUser(issuer *api.Issuer) (*legobridge.RegistrationUser, string, error) {
	// fetch issuer secret
	secretRef := issuer.Spec.ACME.PrivateKeySecretRef
	if secretRef == nil {
		return nil, "", fmt.Errorf("missing secret ref in issuer")
	}
	if issuer.Status.State != api.StateReady {
		if issuer.Status.State != api.StateError {
			return nil, "", &recoverableError{Msg: fmt.Sprintf("referenced issuer not ready: state=%s", issuer.Status.State)}
		}
		return nil, "", fmt.Errorf("referenced issuer not ready: state=%s", issuer.Status.State)
	}
	if issuer.Status.ACME == nil || issuer.Status.ACME.Raw == nil {
		return nil, "", fmt.Errorf("ACME registration missing in status")
	}
	issuerSecretObjectName := resources.NewObjectName(secretRef.Namespace, secretRef.Name)
	issuerSecret := &corev1.Secret{}
	_, err := r.support.GetIssuerSecretResources().GetInto(issuerSecretObjectName, issuerSecret)
	if err != nil {
		return nil, "", errors.Wrap(err, "fetching issuer secret failed")
	}

	reguser, err := legobridge.RegistrationUserFromSecretData(issuer.Spec.ACME.Email, issuer.Status.ACME.Raw, issuerSecret.Data)
	if err != nil {
		return nil, "", errors.Wrap(err, "restoring registration issuer from issuer secret failed")
	}

	return reguser, issuer.Spec.ACME.Server, nil
}

func (r *certReconciler) validateDomainsAndCsr(spec *api.CertificateSpec) error {
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
	err = r.checkDomainRangeRestriction(spec, domainsToValidate)
	return err
}

func (r *certReconciler) issuerName(spec *api.CertificateSpec) string {
	issuerName := r.support.DefaultIssuerName()
	if spec.IssuerRef != nil {
		issuerName = spec.IssuerRef.Name
	}
	return issuerName
}

func (r *certReconciler) issuerObjectName(spec *api.CertificateSpec) resources.ObjectName {
	return resources.NewObjectName(r.support.IssuerNamespace(), r.issuerName(spec))
}

func (r *certReconciler) checkDomainRangeRestriction(spec *api.CertificateSpec, domains []string) error {
	issuerName := r.issuerName(spec)
	if issuerName == r.support.DefaultIssuerName() && r.support.DefaultIssuerDomainRanges() != nil {
		ranges := r.support.DefaultIssuerDomainRanges()
		for _, domain := range domains {
			if !utils.IsInDomainRanges(domain, ranges) {
				return fmt.Errorf("domain %s is not in domain ranges of default issuer (%s)", domain, strings.Join(ranges, ","))
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

func (r *certReconciler) checkForRenewAndSucceeded(logger logger.LogContext, obj resources.Object, secret *corev1.Secret) reconcile.Status {
	crt := obj.Data().(*api.Certificate)

	cert, err := legobridge.DecodeCertificateFromSecretData(secret.Data)
	if err != nil {
		return r.failed(logger, obj, api.StateError, err)
	}
	logger.Infof("certificate valid from %v to %v", cert.NotBefore, cert.NotAfter)
	if r.needsRenewal(cert) {
		if crt.Status.State == api.StatePending && r.lastPendingRateLimiting(crt.Status.LastPendingTimestamp) {
			return reconcile.Succeeded(logger)
		}

		// renew certificate
		return r.obtainCertificateAndPending(logger, obj, secret)
	}
	return r.succeeded(logger, obj)
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
	issuer := r.issuerObjectName(spec)
	hash := r.support.GetIssuerSecretHash(issuer)
	h.Write([]byte(hash))
	h.Write([]byte{0})
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (r *certReconciler) needsRenewal(cert *x509.Certificate) bool {
	return cert.NotAfter.Before(time.Now().Add(r.renewalWindow))
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
	requirement, err := labels.NewRequirement(LabelCertificateHashKey, selection.Equals, []string{specHash})
	if err != nil {
		return nil, "", nil
	}
	objs, err := r.certSecretResources.ListCached(labels.NewSelector().Add(*requirement))
	if err != nil {
		return nil, "", nil
	}

	secretRef, _ := r.determineSecretRef(namespace, spec)
	var best resources.Object
	var bestNotAfter time.Time
	for _, obj := range objs {
		secret := obj.Data().(*corev1.Secret)
		cert, err := legobridge.DecodeCertificateFromSecretData(secret.Data)
		if err != nil {
			continue
		}

		if !r.needsRenewal(cert) {
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

func (r *certReconciler) copySecretIfNeeded(objectMeta metav1.ObjectMeta, secretRef *corev1.SecretReference, specHash string, spec *api.CertificateSpec) (*corev1.SecretReference, error) {
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
	return r.writeCertificateSecret(objectMeta, certificates, specHash, specSecretRef)
}

func (r *certReconciler) writeCertificateSecret(objectMeta metav1.ObjectMeta, certificates *certificate.Resource,
	specHash string, specSecretRef *corev1.SecretReference) (*corev1.SecretReference, error) {
	secret := &corev1.Secret{}
	secret.SetNamespace(core.NormalizeNamespace(objectMeta.GetNamespace()))
	if specSecretRef != nil {
		secret.SetName(specSecretRef.Name)
		// reuse existing secret (especially keep existing annotations and labels)
		obj, err := r.targetCluster.Resources().GetObject(secret)
		if err == nil {
			secret = obj.Data().(*corev1.Secret)
		}
	} else {
		secret.SetGenerateName(objectMeta.GetName() + "-")
	}
	resources.SetLabel(secret, LabelCertificateHashKey, specHash)
	resources.SetLabel(secret, LabelCertificateKey, "true")
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

	obj, err := r.targetCluster.Resources().CreateOrUpdateObject(secret)
	if err != nil && specSecretRef != nil {
		// for migration from cert-manager: check if secret exists with type SecretTypeTLS and retry update with this type
		// (on updating a secret changing the type is not allowed)
		oldSecret := &corev1.Secret{}
		_, err2 := r.targetCluster.Resources().GetObjectInto(resources.NewObjectName(secret.Namespace, secret.Name), oldSecret)
		if err2 == nil {
			if oldSecret.Type == corev1.SecretTypeTLS {
				secret.Type = corev1.SecretTypeTLS
				obj, err = r.targetCluster.Resources().CreateOrUpdateObject(secret)
			}
		}
	}
	if err != nil {
		return nil, errors.Wrap(err, "creating/updating certificate secret failed")
	}

	return &corev1.SecretReference{Name: obj.GetName(), Namespace: obj.GetNamespace()}, nil
}

func (r *certReconciler) updateSecretRefAndSucceeded(logger logger.LogContext, obj resources.Object,
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
		return r.failed(logger, obj, api.StateError, errors.Wrap(err, "updating certificate resource failed"))
	}
	return r.succeeded(logger, obj2)
}

func (r *certReconciler) removeStoredHashKeyAndRepeat(logger logger.LogContext, obj resources.Object) reconcile.Status {
	c := obj.Data().(*api.Certificate)
	delete(c.Labels, LabelCertificateHashKey)
	obj2, err := r.certResources.Update(c)
	if err != nil {
		return r.failed(logger, obj, api.StateError, errors.Wrap(err, "updating certificate resource failed"))
	}
	return r.repeat(logger, obj2)
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

func (r *certReconciler) updateStatus(mod *resources.ModificationState) {
	err := mod.UpdateStatus()
	if err != nil {
		logger.Warnf("updating status failed with: %s", err)
	}
}

func (r *certReconciler) failed(logger logger.LogContext, obj resources.Object, state string, err error) reconcile.Status {
	return r.status(logger, obj, state, err, false)
}

func (r *certReconciler) failedStop(logger logger.LogContext, obj resources.Object, state string, err error) reconcile.Status {
	return r.status(logger, obj, state, err, true)
}

func (r *certReconciler) status(logger logger.LogContext, obj resources.Object, state string, err error, stop bool) reconcile.Status {
	msg := err.Error()

	rerr, isRecoverable := err.(*recoverableError)
	backoffMode := boNone
	if !isRecoverable {
		if stop {
			backoffMode = boStop
		} else {
			backoffMode = boIncrease
		}
	}
	mod, _ := r.prepareUpdateStatus(obj, state, &msg, backoffMode)
	r.updateStatus(mod)

	if isRecoverable {
		if rerr.Interval != 0 {
			return reconcile.Recheck(logger, err, rerr.Interval)
		}
		return reconcile.Delay(logger, err)
	}
	return reconcile.Failed(logger, err)
}

func (r *certReconciler) delay(logger logger.LogContext, obj resources.Object, state string, err error) reconcile.Status {
	return r.status(logger, obj, state, &recoverableError{Msg: err.Error()}, false)
}

func (r *certReconciler) recheck(logger logger.LogContext, obj resources.Object, state string, err error, interval time.Duration) reconcile.Status {
	return r.status(logger, obj, state, &recoverableError{Msg: err.Error(), Interval: interval}, false)
}

func (r *certReconciler) succeeded(logger logger.LogContext, obj resources.Object) reconcile.Status {
	mod, _ := r.prepareUpdateStatus(obj, api.StateReady, nil, boNone)
	r.updateStatus(mod)

	return reconcile.Succeeded(logger)
}

func (r *certReconciler) pending(logger logger.LogContext, obj resources.Object, msg string) reconcile.Status {
	mod, status := r.prepareUpdateStatus(obj, api.StatePending, &msg, boNone)
	status.LastPendingTimestamp = &metav1.Time{Time: time.Now()}
	mod.Modified = true
	r.updateStatus(mod)

	return reconcile.Succeeded(logger)
}

func (r *certReconciler) repeat(logger logger.LogContext, obj resources.Object) reconcile.Status {
	mod, _ := r.prepareUpdateStatus(obj, "", nil, boNone)
	r.updateStatus(mod)

	return reconcile.Repeat(logger)
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

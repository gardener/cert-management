/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package certificate

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/cluster"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	cmlerrors "github.com/gardener/controller-manager-library/pkg/errors"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	cmlutils "github.com/gardener/controller-manager-library/pkg/utils"
	dnsapi "github.com/gardener/external-dns-management/pkg/apis/dns/v1alpha1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-acme/lego/v4/certificate"
	corev1 "k8s.io/api/core/v1"
	apierrrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/cert/source"
	"github.com/gardener/cert-management/pkg/cert/utils"
	ctrl "github.com/gardener/cert-management/pkg/controller"
	"github.com/gardener/cert-management/pkg/controller/issuer/core"
	"github.com/gardener/cert-management/pkg/shared"
	"github.com/gardener/cert-management/pkg/shared/legobridge"
	"github.com/gardener/cert-management/pkg/shared/metrics"
)

const (
	// LabelCertificateNewHashKey is the new label for the certificate hash
	LabelCertificateNewHashKey = api.GroupName + "/hash"
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

	deactivateAuthorizations, _ := c.GetBoolOption(core.OptACMEDeactivateAuthorizations)

	algorithm, _ := c.GetStringOption(core.OptDefaultPrivateKeyAlgorithm)
	rsaSize, _ := c.GetIntOption(core.OptDefaultRSAPrivateKeySize)
	ecdsaSize, _ := c.GetIntOption(core.OptDefaultECDSAPrivateKeySize)
	defaults, err := legobridge.NewCertificatePrivateKeyDefaults(api.PrivateKeyAlgorithm(algorithm), api.PrivateKeySize(rsaSize), api.PrivateKeySize(ecdsaSize)) // #nosec G115 -- only validated values in int32 range are used
	if err != nil {
		return nil, err
	}
	c.Infof(defaults.String())

	dnsCluster := c.GetCluster(ctrl.DNSCluster)
	dnsClient, err := client.New(ptr.To(dnsCluster.Config()), client.Options{})
	if err != nil {
		return nil, fmt.Errorf("creating client for DNS controller failed: %w", err)
	}

	targetClient, err := client.New(ptr.To(targetCluster.Config()), client.Options{})
	if err != nil {
		return nil, fmt.Errorf("creating client for target cluster failed: %w", err)
	}

	reconciler := &certReconciler{
		support:                        support,
		obtainer:                       legobridge.NewObtainer(utils.LoggerFactory),
		classes:                        classes,
		targetCluster:                  targetCluster,
		dnsCluster:                     dnsCluster,
		dnsClient:                      dnsClient,
		certResources:                  certResources,
		certSecretResources:            certSecretResources,
		certSecretClient:               targetClient,
		rateLimiting:                   120 * time.Second,
		pendingRequests:                legobridge.NewPendingRequests(),
		pendingResults:                 legobridge.NewPendingResults(),
		alwaysDeactivateAuthorizations: deactivateAuthorizations,
		certificatePrivateKeyDefaults:  *defaults,
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
	reconciler.useDNSRecords, _ = c.GetBoolOption(core.OptUseDNSRecords)
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
	reconciler.precheckNameservers = shared.PreparePrecheckNameservers(strings.Split(precheckNameservers, ","))
	c.Infof("Using these default nameservers for DNS propagation checks: %s", strings.Join(reconciler.precheckNameservers, ","))

	reconciler.propagationTimeout, _ = c.GetDurationOption(core.OptPropagationTimeout)
	c.Infof("Propagation timeout: %d seconds", int(reconciler.propagationTimeout.Seconds()))
	reconciler.additionalWait, _ = c.GetDurationOption(core.OptPrecheckAdditionalWait)
	c.Infof("Additional wait time: %d seconds", int(reconciler.additionalWait.Seconds()))

	return reconciler, nil
}

type certReconciler struct {
	reconcile.DefaultReconciler
	support                *core.Support
	obtainer               legobridge.Obtainer
	targetCluster          cluster.Interface
	dnsCluster             cluster.Interface
	dnsClient              client.Client
	certResources          resources.Interface
	certSecretResources    resources.Interface
	certSecretClient       client.Client
	rateLimiting           time.Duration
	pendingRequests        *legobridge.PendingCertificateRequests
	pendingResults         *legobridge.PendingResults
	dnsNamespace           *string
	dnsClass               *string
	dnsOwnerID             *string
	useDNSRecords          bool
	precheckNameservers    []string
	additionalWait         time.Duration
	propagationTimeout     time.Duration
	renewalWindow          time.Duration
	renewalOverdueWindow   time.Duration
	classes                *controller.Classes
	cascadeDelete          bool
	garbageCollectorTicker *time.Ticker

	alwaysDeactivateAuthorizations bool
	certificatePrivateKeyDefaults  legobridge.CertificatePrivateKeyDefaults
}

func (r *certReconciler) Start() error {
	if !r.useDNSRecords {
		if err := r.cleanupOrphanDNSEntriesFromOldChallenges(); err != nil {
			return fmt.Errorf("failed cleaning up orphaned DNS entries: %w", err)
		}
	} else {
		if err := r.cleanupOrphanDNSRecordsFromOldChallenges(); err != nil {
			return fmt.Errorf("failed cleaning up orphaned DNS records: %w", err)
		}
	}

	if err := r.cleanupOrphanOutdatedCertificateSecrets(); err != nil {
		return fmt.Errorf("failed cleaning up orphaned, outdated certificate secrets: %w", err)
	}
	r.garbageCollectorTicker = time.NewTicker(7 * 24 * time.Hour)
	go func() {
		for range r.garbageCollectorTicker.C {
			if err := r.cleanupOrphanOutdatedCertificateSecrets(); err != nil {
				logger.Warnf("Garbage collection failed: %v", err)
			}
		}
	}()

	return nil
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

	if r.isOrphanedPendingCertificate(cert) {
		// invalid orphan pending state unfinished from former controller instance, reset status to trigger retry.
		cert.Status.LastPendingTimestamp = nil
		mod, _ := r.prepareUpdateStatus(obj, "", nil, boNone)
		err := mod.UpdateStatus()
		if err != nil {
			return reconcile.Failed(logctx, err)
		}
		return reconcile.Succeeded(logctx)
	}

	if cert.Status.BackOff != nil &&
		obj.GetGeneration() == cert.Status.BackOff.ObservedGeneration &&
		time.Now().Before(cert.Status.BackOff.RetryAfter.Time) {
		interval := time.Until(cert.Status.BackOff.RetryAfter.Time)
		if interval < 1*time.Second {
			interval = 1 * time.Second
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

func (r *certReconciler) isOrphanedPendingCertificate(cert *api.Certificate) bool {
	return cert.Status.State == api.StatePending && !r.challengePending(cert) && r.pendingResults.Peek(client.ObjectKeyFromObject(cert)) == nil
}

func (r *certReconciler) reconcileCert(logctx logger.LogContext, obj resources.Object, cert *api.Certificate) reconcile.Status {
	r.support.AddCertificate(cert)

	if r.challengePending(cert) {
		return reconcile.Recheck(logctx, fmt.Errorf("challenge pending for at least one domain of certificate"), 30*time.Second)
	}

	if result := r.pendingResults.Peek(client.ObjectKeyFromObject(cert)); result != nil {
		status, remove := r.handleObtainOutput(logctx, obj, result)
		if remove {
			r.pendingResults.Remove(client.ObjectKeyFromObject(cert))
		}
		return status
	}

	secretRef, err := r.determineSecretRef(cert.Namespace, &cert.Spec)
	if err != nil {
		return r.failedStop(logctx, obj, api.StateError, err)
	}

	issuerKey := r.support.IssuerClusterObjectKey(cert.Namespace, &cert.Spec)
	issuer, err := r.support.LoadIssuer(issuerKey)
	if err != nil {
		return r.failed(logctx, obj, api.StateError, err)
	}
	if r.support.GetIssuerSecretHash(issuerKey) == "" && issuer.Spec.SelfSigned == nil {
		// issuer not reconciled yet
		logctx.Infof("waiting for reconciliation of issuer %s", issuerKey)
		return reconcile.Delay(logctx, nil)
	}
	var secret *corev1.Secret
	if secretRef != nil {
		secret, err = r.loadSecret(secretRef)
		if err != nil {
			if !apierrrors.IsNotFound(cmlerrors.Cause(err)) {
				return r.failed(logctx, obj, api.StateError, err)
			}
			// ignore if SecretRef is specified but not existing
			// will later be used to store the secret
		} else if x509cert, err := legobridge.DecodeCertificateFromSecretData(secret.Data); err == nil {
			if storedHash := cert.Labels[LabelCertificateNewHashKey]; storedHash != "" {
				specHash := r.buildSpecNewHash(&cert.Spec, issuerKey)
				if specHash != storedHash {
					return r.removeStoredHashKeyAndRepeat(logctx, obj)
				}
				if err := r.updateSecretLabels(obj, secret); err != nil {
					return r.failed(logctx, obj, api.StateError, err)
				}
				if status := r.updateNotAfterAnnotation(logctx, obj, x509cert.NotAfter); status != nil {
					return *status
				}
				return r.checkForRenewAndSucceeded(logctx, obj, secret)
			}

			// corner case: existing secret but no stored hash, check if renewal is overdue
			if r.isRenewalOverdue(x509cert) {
				r.support.SetCertRenewalOverdue(obj.ObjectName())
			}
		}
	}

	if r.lastPendingRateLimiting(cert.Status.LastPendingTimestamp) {
		remainingSeconds := r.lastPendingRateLimitingSeconds(cert.Status.LastPendingTimestamp)
		return reconcile.Delay(logctx, fmt.Errorf("waiting for end of pending rate limiting in %d seconds", remainingSeconds))
	}
	return r.obtainCertificateAndPending(logctx, obj, false)
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
		return r.failed(logctx, obj, api.StateError, fmt.Errorf("obtaining certificate failed: %w", result.Err)), true
	}

	cert, _ := obj.Data().(*api.Certificate)
	specSecretRef, err := r.determineSecretRef(cert.Namespace, &cert.Spec)
	if err != nil {
		return r.failedStop(logctx, obj, api.StateError, err), false
	}

	spec := &api.CertificateSpec{
		CommonName: result.CommonName,
		DNSNames:   result.DNSNames,
		CSR:        result.CSR,
		IssuerRef:  &api.IssuerRef{Name: result.IssuerInfo.Key().Name(), Namespace: result.IssuerInfo.Key().Namespace()},
		PrivateKey: legobridge.FromKeyType(result.KeyType),
	}
	issuerKey := r.support.IssuerClusterObjectKey(cert.Namespace, spec)
	specHash := r.buildSpecNewHash(spec, issuerKey)

	now := time.Now()
	secretRef, err := r.writeCertificateSecret(logctx, result.IssuerInfo, cert.ObjectMeta, result.Certificates, specHash,
		specSecretRef, &now, spec.Keystores, cert.Spec.SecretLabels)
	if err != nil {
		return r.failed(logctx, obj, api.StateError, fmt.Errorf("writing certificate secret failed: %w", err)), false
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
	r.support.RemoveCertificate(key.ObjectName())
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
	seconds := int(time.Until(*endTime).Seconds() + 0.5)
	if seconds > 0 {
		return seconds
	}
	return 0
}

func (r *certReconciler) challengePending(crt *api.Certificate) bool {
	return r.pendingRequests.Contains(client.ObjectKeyFromObject(crt))
}

func (r *certReconciler) obtainCertificateAndPending(logctx logger.LogContext, obj resources.Object, renew bool) reconcile.Status {
	cert := obj.Data().(*api.Certificate)
	logctx.Infof("obtain certificate")

	issuerKey := r.support.IssuerClusterObjectKey(cert.Namespace, &cert.Spec)
	issuer, err := r.support.LoadIssuer(issuerKey)
	if err != nil {
		return r.failed(logctx, obj, api.StateError, err)
	}

	if hasMultipleIssuerTypes(issuer) {
		return r.failed(logctx, obj, api.StateError, fmt.Errorf("invalid issuer spec: either ACME, CA or selfSigned can be set"))
	}
	if issuer.Spec.ACME != nil {
		return r.obtainCertificateAndPendingACME(logctx, obj, renew, cert, issuerKey, issuer)
	}
	if issuer.Spec.CA != nil {
		return r.obtainCertificateCA(logctx, obj, renew, cert, issuerKey, issuer)
	}
	if issuer.Spec.SelfSigned != nil {
		return r.obtainCertificateSelfSigned(logctx, obj, renew, cert, issuerKey)
	}
	return r.failed(logctx, obj, api.StateError, fmt.Errorf("incomplete issuer spec (ACME or CA section must be provided)"))
}

type notAcceptedError struct {
	message  string
	waitTime time.Duration
}

func (e *notAcceptedError) Error() string {
	return e.message
}

func (r *certReconciler) obtainCertificateAndPendingACME(logctx logger.LogContext, obj resources.Object,
	renew bool, cert *api.Certificate, issuerKey utils.IssuerKey, issuer *api.Issuer) reconcile.Status {
	reguser, err := r.support.RestoreRegUser(issuerKey, issuer)
	if err != nil {
		return r.failed(logctx, obj, api.StateError, err)
	}
	if cert.Spec.Duration != nil {
		return r.failedStop(logctx, obj, api.StateError, fmt.Errorf("duration cannot be set for ACME certificate"))
	}
	if cert.Spec.IsCA != nil {
		return r.failedStop(logctx, obj, api.StateError, fmt.Errorf("isCA cannot be set for ACME certificate"))
	}
	err = r.validateDomainsAndCsr(&cert.Spec, issuer.Spec.ACME.Domains, issuerKey)
	if err != nil {
		return r.failedStop(logctx, obj, api.StateError, err)
	}

	if secretRef, specHash, notAfter := r.findSecretByHashLabel(cert.Namespace, &cert.Spec); secretRef != nil {
		// reuse found certificate
		issuerInfo := shared.NewACMEIssuerInfo(issuerKey)
		secretRef, err := r.copySecretIfNeeded(logctx, issuerInfo, cert.ObjectMeta, secretRef, specHash, &cert.Spec)
		if err != nil {
			return r.failed(logctx, obj, api.StateError, err)
		}
		return r.updateSecretRefAndSucceeded(logctx, obj, secretRef, specHash, notAfter)
	}

	preflightCheck := func() error {
		if accepted, requestsPerDayQuota := r.support.TryAcceptCertificateRequest(issuerKey); !accepted {
			waitMinutes := 1
			if requestsPerDayQuota == 0 {
				return &notAcceptedError{
					message:  fmt.Sprintf("request quota lookup failed for issuer %s. Retrying in %d min. ", issuerKey, waitMinutes),
					waitTime: time.Duration(waitMinutes) * time.Minute,
				}
			}
			waitMinutes = 1440 / requestsPerDayQuota / 2
			if waitMinutes < 5 {
				waitMinutes = 5
			}
			return &notAcceptedError{
				message: fmt.Sprintf("request quota exhausted. Retrying in %d min. "+
					"Up to %d requests per day are allowed. To change the quota, set `spec.requestsPerDayQuota` for issuer %s",
					waitMinutes, requestsPerDayQuota, issuerKey),
				waitTime: time.Duration(waitMinutes) * time.Minute,
			}
		}
		return nil
	}

	objectKey := client.ObjectKeyFromObject(cert)
	sublogctx := logctx.NewContext("callback", cert.Name)
	callback := func(output *legobridge.ObtainOutput) {
		r.pendingRequests.Remove(objectKey)
		r.pendingResults.Add(objectKey, output)
		key := resources.NewClusterKey(r.targetCluster.GetId(), api.Kind(api.CertificateKind), objectKey.Namespace, objectKey.Name)
		err := r.support.EnqueueKey(key)
		if err != nil {
			sublogctx.Warnf("Enqueue %s failed with %s", objectKey, err.Error())
		}
	}
	var dnsSettings *legobridge.DNSControllerSettings
	if issuer.Spec.ACME.SkipDNSChallengeValidation == nil || !*issuer.Spec.ACME.SkipDNSChallengeValidation {
		followCNAME := false
		if cert.Spec.FollowCNAME != nil && *cert.Spec.FollowCNAME {
			followCNAME = true
		}
		precheckNameservers := r.precheckNameservers
		if issuer.Spec.ACME.PrecheckNameservers != nil {
			precheckNameservers = shared.PreparePrecheckNameservers(issuer.Spec.ACME.PrecheckNameservers)
		}
		dnsSettings = &legobridge.DNSControllerSettings{
			Client:              r.dnsClient,
			Namespace:           cert.Namespace,
			OwnerID:             r.dnsOwnerID,
			PrecheckNameservers: precheckNameservers,
			AdditionalWait:      r.additionalWait,
			PropagationTimeout:  r.propagationTimeout,
			FollowCNAME:         followCNAME,
		}
		if r.dnsNamespace != nil {
			dnsSettings.Namespace = *r.dnsNamespace
		}
		if r.useDNSRecords {
			dnsSettings.DNSRecordSettings, err = createDNSRecordSettings(cert)
			if err != nil {
				return r.failed(logctx, obj, api.StateError, err)
			}
		}
	}
	targetDNSClass := ""
	if r.dnsClass != nil {
		targetDNSClass = *r.dnsClass
	}
	preferredChain := ""
	if cert.Spec.PreferredChain != nil {
		preferredChain = *cert.Spec.PreferredChain
	}
	keyType, err := r.certificatePrivateKeyDefaults.ToKeyType(cert.Spec.PrivateKey)
	if err != nil {
		return r.failed(logctx, obj, api.StateError, fmt.Errorf("invalid private key configuration: %w", err))
	}

	input := legobridge.ObtainInput{
		User:                           reguser,
		DNSSettings:                    dnsSettings,
		IssuerKey:                      issuerKey,
		CommonName:                     cert.Spec.CommonName,
		DNSNames:                       cert.Spec.DNSNames,
		CSR:                            cert.Spec.CSR,
		TargetClass:                    targetDNSClass,
		Callback:                       callback,
		RequestName:                    client.ObjectKey{Namespace: obj.GetNamespace(), Name: obj.GetName()},
		Renew:                          renew,
		AlwaysDeactivateAuthorizations: r.alwaysDeactivateAuthorizations,
		PreferredChain:                 preferredChain,
		KeyType:                        keyType,
		PreflightCheck:                 preflightCheck,
	}

	err = r.obtainer.Obtain(input)
	if err != nil {
		var concurrentObtainError *legobridge.ConcurrentObtainError
		var notAcceptedError *notAcceptedError
		switch {
		case errors.As(err, &concurrentObtainError):
			return r.delay(logctx, obj, api.StateWaiting, err)
		case errors.As(err, &notAcceptedError):
			return r.recheck(logctx, obj, api.StateWaiting, err, notAcceptedError.waitTime)
		default:
			return r.failed(logctx, obj, api.StateError, fmt.Errorf("preparing obtaining certificates failed: %w", err))
		}
	}
	r.pendingRequests.Add(objectKey)
	msg := "certificate requested, preparing/waiting for successful DNS01 challenge"
	return r.pending(logctx, obj, msg)
}

func (r *certReconciler) restoreCA(issuerKey utils.IssuerKey, issuer *api.Issuer) (*legobridge.TLSKeyPair, error) {
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
	secretResources, err := r.support.GetIssuerSecretResources(issuerKey)
	if err != nil {
		return nil, fmt.Errorf("fetching issuer secret failed: %w", err)
	}
	issuerSecret := &corev1.Secret{}
	_, err = secretResources.GetInto(issuerSecretObjectName, issuerSecret)
	if err != nil {
		return nil, fmt.Errorf("fetching issuer secret failed: %w", err)
	}

	CAKeyPair, err := legobridge.CAKeyPairFromSecretData(issuerSecret.Data)
	if err != nil {
		return nil, fmt.Errorf("restoring CA issuer from issuer secret failed: %w", err)
	}

	return CAKeyPair, nil
}

func (r *certReconciler) obtainCertificateSelfSigned(logctx logger.LogContext, obj resources.Object,
	renew bool, cert *api.Certificate, issuerKey utils.IssuerKey) reconcile.Status {
	if cert.Spec.IsCA == nil || !*cert.Spec.IsCA {
		return r.failedStop(logctx, obj, api.StateError, fmt.Errorf("self signed certificates must set 'spec.isCA: true'"))
	}
	duration, err := r.getDuration(cert)
	if err != nil {
		return r.failedStop(logctx, obj, api.StateError, err)
	}
	if duration == nil {
		duration = ptr.To(legobridge.DefaultCertDuration)
	}
	err = r.validateDomainsAndCsr(&cert.Spec, nil, issuerKey)
	if err != nil {
		return r.failedStop(logctx, obj, api.StateError, err)
	}

	if secretRef, specHash, notAfter := r.findSecretByHashLabel(cert.Namespace, &cert.Spec); secretRef != nil {
		// reuse found certificate
		issuerInfo := shared.NewSelfSignedIssuerInfo(issuerKey)
		secretRef, err := r.copySecretIfNeeded(logctx, issuerInfo, cert.ObjectMeta, secretRef, specHash, &cert.Spec)
		if err != nil {
			return r.failed(logctx, obj, api.StateError, err)
		}
		return r.updateSecretRefAndSucceeded(logctx, obj, secretRef, specHash, notAfter)
	}

	objectKey := client.ObjectKeyFromObject(cert)
	sublogctx := logctx.NewContext("callback", cert.Name)
	callback := func(output *legobridge.ObtainOutput) {
		r.pendingResults.Add(objectKey, output)
		r.pendingRequests.Remove(objectKey)
		key := resources.NewClusterKey(r.targetCluster.GetId(), api.Kind(api.CertificateKind), objectKey.Namespace, objectKey.Name)
		err := r.support.EnqueueKey(key)
		if err != nil {
			sublogctx.Warnf("Enqueue %s failed with %s", objectKey, err.Error())
		}
	}

	keyType, err := r.certificatePrivateKeyDefaults.ToKeyType(cert.Spec.PrivateKey)
	if err != nil {
		return r.failedStop(logctx, obj, api.StateError, err)
	}
	input := legobridge.ObtainInput{
		IssuerKey:  issuerKey,
		CommonName: cert.Spec.CommonName,
		DNSNames:   cert.Spec.DNSNames,
		Callback:   callback,
		Renew:      renew,
		KeyType:    keyType,
		IsCA:       true,
		Duration:   duration,
		CSR:        cert.Spec.CSR,
	}

	err = r.obtainer.Obtain(input)
	if err != nil {
		return r.failed(logctx, obj, api.StateError, fmt.Errorf("obtaining self signed certificate failed: %w", err))
	}

	r.pendingRequests.Add(objectKey)
	msg := "self signed certificate requested, waiting for creation"
	return r.pending(logctx, obj, msg)
}

func (r *certReconciler) obtainCertificateCA(logctx logger.LogContext, obj resources.Object,
	renew bool, cert *api.Certificate, issuerKey utils.IssuerKey, issuer *api.Issuer) reconcile.Status {
	if cert.Spec.IsCA != nil {
		return r.failedStop(logctx, obj, api.StateError, fmt.Errorf("isCA cannot be set for a certificate with issuer of type 'ca'"))
	}
	CAKeyPair, err := r.restoreCA(issuerKey, issuer)
	if err != nil {
		return r.failed(logctx, obj, api.StateError, err)
	}

	duration, err := r.getDuration(cert)
	if err != nil {
		return r.failedStop(logctx, obj, api.StateError, err)
	}
	if duration == nil {
		duration = ptr.To(2 * legobridge.DefaultCertDuration)
	}
	err = r.validateCertDuration(duration, CAKeyPair)
	if err != nil {
		return r.failedStop(logctx, obj, api.StateError, err)
	}
	err = r.validateDomainsAndCsr(&cert.Spec, nil, issuerKey)
	if err != nil {
		return r.failedStop(logctx, obj, api.StateError, err)
	}

	if secretRef, specHash, notAfter := r.findSecretByHashLabel(cert.Namespace, &cert.Spec); secretRef != nil {
		// reuse found certificate
		issuerInfo := shared.NewCAIssuerInfo(issuerKey)
		secretRef, err := r.copySecretIfNeeded(logctx, issuerInfo, cert.ObjectMeta, secretRef, specHash, &cert.Spec)
		if err != nil {
			return r.failed(logctx, obj, api.StateError, err)
		}
		return r.updateSecretRefAndSucceeded(logctx, obj, secretRef, specHash, notAfter)
	}

	objectKey := client.ObjectKeyFromObject(cert)
	sublogctx := logctx.NewContext("callback", cert.Name)
	callback := func(output *legobridge.ObtainOutput) {
		r.pendingRequests.Remove(objectKey)
		r.pendingResults.Add(objectKey, output)
		key := resources.NewClusterKey(r.targetCluster.GetId(), api.Kind(api.CertificateKind), objectKey.Namespace, objectKey.Name)
		err := r.support.EnqueueKey(key)
		if err != nil {
			sublogctx.Warnf("Enqueue %s failed with %s", objectKey, err.Error())
		}
	}

	input := legobridge.ObtainInput{CAKeyPair: CAKeyPair, IssuerKey: issuerKey,
		CommonName: cert.Spec.CommonName, DNSNames: cert.Spec.DNSNames, CSR: cert.Spec.CSR,
		Callback: callback, Renew: renew, Duration: duration}

	err = r.obtainer.Obtain(input)
	if err != nil {
		var concurrentObtainError *legobridge.ConcurrentObtainError
		switch {
		case errors.As(err, &concurrentObtainError):
			return r.delay(logctx, obj, api.StatePending, err)
		default:
			return r.failed(logctx, obj, api.StateError, fmt.Errorf("preparing obtaining certificates failed: %w", err))
		}
	}
	r.pendingRequests.Add(objectKey)

	msg := "certificate requested, waiting for creation by CA"
	return r.pending(logctx, obj, msg)
}

func (r *certReconciler) validateDomainsAndCsr(spec *api.CertificateSpec, issuerDomains *api.DNSSelection, issuerKey utils.IssuerKey) error {
	domainsToValidate, err := utils.ExtractDomains(spec)
	if err != nil {
		return err
	}

	names := sets.Set[string]{}
	for _, name := range domainsToValidate {
		if names.Has(name) {
			return fmt.Errorf("duplicate domain: %s", name)
		}
		names.Insert(name)
	}
	err = r.checkDomainRangeRestriction(issuerDomains, domainsToValidate, issuerKey)
	return err
}

func (r *certReconciler) checkDomainRangeRestriction(issuerDomains *api.DNSSelection, domains []string, issuerKey utils.IssuerKey) error {
	if r.support.IsDefaultIssuer(issuerKey) && r.support.DefaultIssuerDomainRanges() != nil {
		ranges := r.support.DefaultIssuerDomainRanges()
		for _, domain := range domains {
			if !utils.IsInDomainRanges(domain, ranges) {
				return fmt.Errorf("domain %s is not in domain ranges of default issuer (%s)", domain, strings.Join(ranges, ","))
			}
		}
	}
	if issuerDomains != nil {
		for _, domain := range domains {
			if len(issuerDomains.Exclude) > 0 && utils.IsInDomainRanges(domain, issuerDomains.Exclude) {
				return fmt.Errorf("domain %s is an excluded domain of issuer %s (excluded: %s)",
					domain, issuerKey, strings.Join(issuerDomains.Exclude, ","))
			}
			if !utils.IsInDomainRanges(domain, issuerDomains.Include) {
				return fmt.Errorf("domain %s is not an included domain of issuer %s (included: %s)",
					domain, issuerKey, strings.Join(issuerDomains.Include, ","))
			}
		}
	}
	return nil
}

func (r *certReconciler) getDuration(cert *api.Certificate) (*time.Duration, error) {
	if cert.Spec.Duration == nil {
		return nil, nil
	}
	duration := cert.Spec.Duration.Duration
	if duration < 2*r.renewalWindow {
		return nil, fmt.Errorf("certificate duration must be greater than %v", 2*r.renewalWindow)
	}
	return ptr.To(duration), nil
}

func (r *certReconciler) validateCertDuration(duration *time.Duration, caKeyPair *legobridge.TLSKeyPair) error {
	if duration == nil {
		return nil
	}
	caNotAfter := caKeyPair.Cert.NotAfter
	now := time.Now()
	if now.Add(*duration).After(caNotAfter) {
		return fmt.Errorf("certificate lifetime (%v) is longer than the lifetime of the CA certificate (%v)", now.Add(*duration), caNotAfter)
	}
	return nil
}

func (r *certReconciler) loadSecret(secretRef *corev1.SecretReference) (*corev1.Secret, error) {
	secretObjectName := resources.NewObjectName(secretRef.Namespace, secretRef.Name)
	secret := &corev1.Secret{}
	_, err := r.certSecretResources.GetInto(secretObjectName, secret)
	if err != nil {
		return nil, fmt.Errorf("fetching certificate secret failed: %w", err)
	}

	return secret, nil
}

func (r *certReconciler) updateSecretLabels(obj resources.Object, secret *corev1.Secret) error {
	crt := obj.Data().(*api.Certificate)
	modified := false
	for k, v := range crt.Spec.SecretLabels {
		if secret.Labels[k] != v {
			resources.SetLabel(secret, k, v)
			modified = true
		}
	}
	if modified {
		_, err := r.certSecretResources.Update(secret)
		return err
	}
	return nil
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
		return r.obtainCertificateAndPending(logctx, obj, true)
	}
	if revoked {
		return r.revoked(logctx, obj)
	}

	msg := fmt.Sprintf("certificate (SN %s) valid from %v to %v", SerialNumberToString(cert.SerialNumber, false), cert.NotBefore, cert.NotAfter)
	logctx.Infof(msg)
	if err := r.updateKeystoresIfSpecChanged(logctx, secret, crt.Spec.Keystores); err != nil {
		return r.failed(logctx, obj, api.StateError, err)
	}
	return r.succeeded(logctx, obj, &msg)
}

func (r *certReconciler) updateNotAfterAnnotation(logctx logger.LogContext, obj resources.Object, notAfter time.Time) *reconcile.Status {
	notAfterStr := notAfter.Format(time.RFC3339)
	if obj.GetAnnotation(AnnotationNotAfter) != notAfterStr {
		crt := obj.Data().(*api.Certificate)
		resources.SetAnnotation(crt, AnnotationNotAfter, notAfterStr)
		if err := obj.Update(); err != nil {
			status := r.failed(logctx, obj, crt.Status.State, fmt.Errorf("updating annotation: %w", err))
			return &status
		}
	}
	return nil
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
			status := r.failed(logctx, obj, crt.Status.State, fmt.Errorf("requesting renewal: %w", err))
			return &status
		}
		status := reconcile.RescheduleAfter(logctx, 1*time.Second)
		return &status
	}
	return nil
}

func (r *certReconciler) buildSpecNewHash(spec *api.CertificateSpec, issuerKey utils.IssuerKey) string {
	h := sha256.New224()
	if spec.CommonName != nil {
		h.Write([]byte(*spec.CommonName))
		h.Write([]byte{0})
	}
	for _, domain := range spec.DNSNames {
		h.Write([]byte(domain))
		h.Write([]byte{0})
	}
	if spec.CSR != nil {
		h.Write([]byte{0})
		h.Write(spec.CSR)
		h.Write([]byte{0})
	}
	h.Write([]byte(issuerKey.String()))
	h.Write([]byte{0})
	if keyType, err := r.certificatePrivateKeyDefaults.ToKeyType(spec.PrivateKey); err == nil && !r.certificatePrivateKeyDefaults.IsDefaultKeyType(keyType) {
		h.Write([]byte(keyType))
		h.Write([]byte{0})
	}
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
		if spec.SecretRef.Name == "" {
			return nil, fmt.Errorf("secretRef.name must not be empty if specified")
		}
		if spec.SecretName != nil && *spec.SecretName != spec.SecretRef.Name {
			return nil, fmt.Errorf("conflicting names in secretRef.Name and secretName: %s != %s", spec.SecretRef.Name, *spec.SecretName)
		}
		if spec.SecretRef.Namespace != "" {
			ns = spec.SecretRef.Namespace
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
	issuerKey := r.support.IssuerClusterObjectKey(namespace, spec)
	specHash := r.buildSpecNewHash(spec, issuerKey)
	objs, err := FindAllCertificateSecretsByNewHashLabel(r.certSecretResources, specHash)
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

func (r *certReconciler) copySecretIfNeeded(logctx logger.LogContext, issuerInfo shared.IssuerInfo,
	objectMeta metav1.ObjectMeta, secretRef *corev1.SecretReference, specHash string, spec *api.CertificateSpec) (*corev1.SecretReference, error) {
	ns := core.NormalizeNamespace(objectMeta.Namespace)
	specSecretRef, _ := r.determineSecretRef(ns, spec)
	if specSecretRef != nil && secretRef.Name == specSecretRef.Name &&
		(secretRef.Namespace == specSecretRef.Namespace || (secretRef.Namespace == "" && specSecretRef.Namespace == ns)) {
		return specSecretRef, nil
	}
	secret, err := r.loadSecret(secretRef)
	if err != nil {
		return nil, err
	}
	certificates := legobridge.SecretDataToCertificates(secret.Data)

	requestedAt := ExtractRequestedAtFromAnnotation(secret)
	return r.writeCertificateSecret(logctx, issuerInfo, objectMeta, certificates, specHash, specSecretRef, requestedAt, spec.Keystores, spec.SecretLabels)
}

func (r *certReconciler) writeCertificateSecret(logctx logger.LogContext, issuerInfo shared.IssuerInfo, objectMeta metav1.ObjectMeta,
	certificates *certificate.Resource, specHash string, specSecretRef *corev1.SecretReference,
	requestedAt *time.Time, keystores *api.CertificateKeystores,
	secretLabels map[string]string) (*corev1.SecretReference, error) {
	secret := &corev1.Secret{
		Type: corev1.SecretTypeTLS,
	}
	secret.SetNamespace(core.NormalizeNamespace(objectMeta.GetNamespace()))
	if specSecretRef != nil {
		secret.SetName(specSecretRef.Name)
		if specSecretRef.Namespace != "" {
			secret.SetNamespace(specSecretRef.Namespace)
		}
		// reuse existing secret (especially keep existing annotations and labels)
		obj, err := r.certSecretResources.GetInto1(secret)
		if err == nil {
			secret = obj.Data().(*corev1.Secret)
		}
	} else {
		secret.SetGenerateName(objectMeta.GetName() + "-")
	}
	for k, v := range secretLabels {
		resources.SetLabel(secret, k, v)
	}
	resources.SetLabel(secret, LabelCertificateNewHashKey, specHash)
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

	err := r.addKeystores(secret, keystores)
	if err != nil {
		return nil, fmt.Errorf("adding keystores to secret failed: %w", err)
	}
	obj, err := r.certSecretResources.CreateOrUpdate(secret)
	if err != nil {
		return nil, fmt.Errorf("creating/updating certificate secret failed: %w", err)
	}
	legobridge.RemoveKeystoresFromSecret(secret)

	ref, created, err := BackupSecret(r.certSecretResources, secret, specHash, issuerInfo)
	if err != nil {
		logctx.Warnf("Backup of secret %s/%s failed: %s", secret.Namespace, secret.Name, err)
	} else if created {
		logctx.Infof("Created backup secret %s/%s", ref.Namespace, ref.Name)
	}

	return &corev1.SecretReference{Name: obj.GetName(), Namespace: obj.GetNamespace()}, nil
}

func (r *certReconciler) addKeystores(secret *corev1.Secret, keystores *api.CertificateKeystores) error {
	return legobridge.AddKeystoresToSecret(context.Background(), r.certSecretClient, secret, keystores)
}

func (r *certReconciler) updateKeystoresIfSpecChanged(logctx logger.LogContext, secret *corev1.Secret, keystores *api.CertificateKeystores) error {
	modified, err := legobridge.UpdateKeystoresToSecret(context.Background(), r.certSecretClient, secret, keystores)
	if err != nil {
		return err
	}
	if !modified {
		return nil
	}
	_, err = r.certSecretResources.CreateOrUpdate(secret)
	if err != nil {
		return fmt.Errorf("creating/updating certificate secret for keystores failed: %w", err)
	}
	logctx.Infof("updated keystores in certificate secret")
	return nil
}

func (r *certReconciler) updateSecretRefAndSucceeded(logctx logger.LogContext, obj resources.Object,
	secretRef *corev1.SecretReference, specHash string, notAfter *time.Time) reconcile.Status {
	crt := obj.Data().(*api.Certificate)
	crt.Spec.SecretRef = secretRef
	if crt.Labels == nil {
		crt.Labels = map[string]string{}
	}
	crt.Labels[LabelCertificateNewHashKey] = specHash
	if notAfter != nil {
		resources.SetAnnotation(crt, AnnotationNotAfter, notAfter.Format(time.RFC3339))
	} else {
		resources.RemoveAnnotation(crt, AnnotationNotAfter)
	}
	obj2, err := r.certResources.Update(crt)
	if err != nil {
		return r.failed(logctx, obj, api.StateError, fmt.Errorf("updating certificate resource failed: %w", err))
	}
	return r.succeeded(logctx, obj2, nil)
}

func (r *certReconciler) removeStoredHashKeyAndRepeat(logctx logger.LogContext, obj resources.Object) reconcile.Status {
	c := obj.Data().(*api.Certificate)
	delete(c.Labels, LabelCertificateNewHashKey)
	obj2, err := r.certResources.Update(c)
	if err != nil {
		return r.failed(logctx, obj, api.StateError, fmt.Errorf("updating certificate resource failed: %w", err))
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

	status.Conditions = r.updateReadyCondition(mod, status.Conditions, state, msg, status.ObservedGeneration)

	cn := crt.Spec.CommonName
	dnsNames := crt.Spec.DNSNames
	if crt.Spec.CSR != nil {
		cn, dnsNames, _ = shared.ExtractCommonNameAnDNSNames(crt.Spec.CSR)
	}
	mod.AssureStringPtrPtr(&status.CommonName, cn)
	utils.AssureStringSlice(mod.ModificationState, &status.DNSNames, dnsNames)

	var expirationDate *string
	notAfter, ok := resources.GetAnnotation(crt, AnnotationNotAfter)
	if ok {
		expirationDate = &notAfter
	}
	mod.AssureStringPtrPtr(&status.ExpirationDate, expirationDate)

	issuerKey := r.support.IssuerClusterObjectKey(crt.Namespace, &crt.Spec)
	newRef := api.QualifiedIssuerRef{Cluster: issuerKey.ClusterName(), Name: issuerKey.Name(), Namespace: issuerKey.NamespaceOrDefault(r.support.IssuerNamespace())}
	if status.IssuerRef == nil || !reflect.DeepEqual(*status.IssuerRef, newRef) {
		status.IssuerRef = &newRef
		mod.Modify(true)
	}

	return mod, status
}

func (r *certReconciler) updateReadyCondition(mod *resources.ModificationState, oldConditions []metav1.Condition,
	state string, msg *string, observedGeneration int64) []metav1.Condition {
	if state == "" {
		// ignore intermediate state
		return oldConditions
	}
	oldReadyCondition := &metav1.Condition{
		Type:               api.CertificateConditionReady,
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
	if len(oldConditions) == 1 && oldConditions[0].Type == api.CertificateConditionReady {
		oldReadyCondition = &oldConditions[0]
	}
	status := metav1.ConditionFalse
	message := cmlutils.StringValue(msg)
	if state == api.StateReady {
		status = metav1.ConditionTrue
		message = ""
	}
	newReadyCondition := metav1.Condition{
		Type:               api.CertificateConditionReady,
		Status:             status,
		Message:            message,
		ObservedGeneration: observedGeneration,
		Reason:             state,
		LastTransitionTime: oldReadyCondition.LastTransitionTime,
	}
	modified := false
	if oldReadyCondition.Status != newReadyCondition.Status {
		newReadyCondition.LastTransitionTime = metav1.NewTime(time.Now())
		modified = true
	}
	modified = modified || oldReadyCondition.Message != newReadyCondition.Message
	modified = modified || oldReadyCondition.ObservedGeneration != newReadyCondition.ObservedGeneration
	modified = modified || oldReadyCondition.Reason != newReadyCondition.Reason
	if modified {
		mod.Modify(true)
		return []metav1.Condition{newReadyCondition}
	}
	return oldConditions
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

	var rerr *core.RecoverableError
	isRecoverable := errors.As(err, &rerr)
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
	return r.recheck(logctx, obj, state, err, 30*time.Second)
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

func (r *certReconciler) cleanupOrphanDNSEntriesFromOldChallenges() error {
	// find orphan dnsentries from DNSChallenges and try to delete them
	// should only happen if cert-manager is terminated during running DNS challenge(s)

	entriesResource, err := r.dnsCluster.Resources().GetByExample(&dnsapi.DNSEntry{})
	if err != nil {
		return fmt.Errorf("issuer: cleanupOrphanDNSEntriesFromOldChallenges failed with: %w", err)
	}
	var objects []resources.Object
	if r.dnsNamespace != nil {
		objects, err = entriesResource.Namespace(*r.dnsNamespace).List(metav1.ListOptions{})
	} else {
		objects, err = entriesResource.List(metav1.ListOptions{})
	}
	if err != nil {
		return fmt.Errorf("issuer: cleanupOrphanDNSEntriesFromOldChallenges failed with: %w", err)
	}
	count := 0
	expectedClass := ""
	if r.dnsClass != nil {
		expectedClass = *r.dnsClass
	}
	for _, obj := range objects {
		class, _ := resources.GetAnnotation(obj.Data(), shared.AnnotDNSClass)
		challenge, _ := resources.GetAnnotation(obj.Data(), shared.AnnotACMEDNSChallenge)
		if challenge != "" && class == expectedClass {
			err = entriesResource.Delete(obj.Data())
			if err != nil {
				logger.Warnf("issuer: deleting DNS entry %s/%s failed with: %s", obj.GetNamespace(), obj.GetName(), err)
			} else {
				count++
			}
		}
	}
	logger.Infof("issuer: cleanup: %d orphan DNS entries deleted", count)
	return nil
}

func (r *certReconciler) cleanupOrphanDNSRecordsFromOldChallenges() error {
	// find orphan dnsentries from DNSChallenges and try to delete them
	// should only happen if cert-manager is terminated during running DNS challenge(s)

	recordsResource, err := r.dnsCluster.Resources().GetByExample(&extensionsv1alpha.DNSRecord{})
	if err != nil {
		return fmt.Errorf("issuer: cleanupOrphanDNSRecordsFromOldChallenges failed with: %w", err)
	}
	var objects []resources.Object
	if r.dnsNamespace != nil {
		objects, err = recordsResource.Namespace(*r.dnsNamespace).List(metav1.ListOptions{})
	} else {
		objects, err = recordsResource.List(metav1.ListOptions{})
	}
	if err != nil {
		return fmt.Errorf("issuer: cleanupOrphanDNSRecordsFromOldChallenges failed with: %w", err)
	}
	count := 0
	for _, obj := range objects {
		challenge, _ := resources.GetAnnotation(obj.Data(), shared.AnnotACMEDNSChallenge)
		if challenge != "" {
			if resources.SetAnnotation(obj.Data(), v1beta1constants.ConfirmationDeletion, "true") {
				if _, err := recordsResource.Update(obj.Data()); err != nil {
					logger.Warnf("issuer: annotating DNSRecord %s/%s failed: %w", obj.GetNamespace(), obj.GetName(), err)
					continue
				}
			}

			err = recordsResource.Delete(obj.Data())
			if err != nil {
				logger.Warnf("issuer: deleting DNSRecord %s/%s failed with: %s", obj.GetNamespace(), obj.GetName(), err)
				continue
			}
			count++
		}
	}
	logger.Infof("issuer: cleanup: %d orphan DNSRecords deleted", count)
	return nil
}

// cleanupOrphanOutdatedCertificateSecrets performs a garbage collection of orphan secrets.
// A certificate secret is deleted if it is not referenced by a certificate custom resource and
// if its TLS certificate is not valid since at least 14 days.
func (r *certReconciler) cleanupOrphanOutdatedCertificateSecrets() error {
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
		return fmt.Errorf("%slist secrets failed with %w", prefix, err)
	}
	certs, err := r.certResources.List(metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("%slist certificates failed with %w", prefix, err)
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
	return nil
}

func createDNSRecordSettings(cert *api.Certificate) (*legobridge.DNSRecordSettings, error) {
	typ := cert.Annotations[source.AnnotDNSRecordProviderType]
	if typ == "" {
		return nil, fmt.Errorf("missing annotation %s for creating DNSRecord", source.AnnotDNSRecordProviderType)
	}
	ref := cert.Annotations[source.AnnotDNSRecordSecretRef]
	if ref == "" {
		return nil, fmt.Errorf("missing annotation %s for creating DNSRecord", source.AnnotDNSRecordSecretRef)
	}
	parts := strings.SplitN(ref, "/", 2)
	var secretRef corev1.SecretReference
	if len(parts) == 1 {
		secretRef.Namespace = cert.Namespace
		secretRef.Name = parts[0]
	} else {
		secretRef.Namespace = parts[0]
		secretRef.Name = parts[1]
	}
	return &legobridge.DNSRecordSettings{
		Type:      typ,
		SecretRef: secretRef,
		Class:     cert.Annotations[source.AnnotDNSRecordClass],
	}, nil
}

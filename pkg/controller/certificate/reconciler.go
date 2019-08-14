/*
 * Copyright 2019 SAP SE or an SAP affiliate company. All rights reserved. rr file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use rr file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 *
 */

package certificate

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/go-acme/lego/certificate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/cluster"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/cert/legobridge"
	"github.com/gardener/cert-management/pkg/cert/utils"
	ctrl "github.com/gardener/cert-management/pkg/controller"
)

func CertReconciler(c controller.Interface) (reconcile.Interface, error) {
	defaultCluster := c.GetCluster(ctrl.DefaultCluster)
	issuerResources, err := defaultCluster.Resources().GetByExample(&api.Issuer{})
	if err != nil {
		return nil, err
	}
	issuerSecretResources, err := defaultCluster.Resources().GetByExample(&corev1.Secret{})
	if err != nil {
		return nil, err
	}

	targetCluster := c.GetCluster(ctrl.TargetCluster)
	certResources, err := targetCluster.Resources().GetByExample(&api.Certificate{})
	if err != nil {
		return nil, err
	}
	certSecretResources, err := targetCluster.Resources().GetByExample(&corev1.Secret{})
	if err != nil {
		return nil, err
	}

	dnsCluster := c.GetCluster(ctrl.DNSCluster)
	reconciler := &certReconciler{
		Interface:             c,
		targetCluster:         targetCluster,
		dnsCluster:            dnsCluster,
		issuerResources:       issuerResources,
		issuerSecretResources: issuerSecretResources,
		certResources:         certResources,
		certSecretResources:   certSecretResources,
		rateLimiting:          120 * time.Second,
		pendingRequests:       legobridge.NewPendingRequests(),
		pendingResults:        legobridge.NewPendingResults(),
	}

	reconciler.defaultIssuer, _ = c.GetStringOption(OptDefaultIssuer)
	reconciler.issuerNamespace, _ = c.GetStringOption(OptIssuerNamespace)
	reconciler.defaultIssuerDomainRange, _ = c.GetStringOption(OptDefaultIssuerDomainRange)
	reconciler.defaultIssuerDomainRange = utils.NormalizeDomainRange(reconciler.defaultIssuerDomainRange)

	dnsNamespace, _ := c.GetStringOption(OptDnsNamespace)
	if dnsNamespace != "" {
		reconciler.dnsNamespace = &dnsNamespace
	}
	dnsOwnerId, _ := c.GetStringOption(OptDnsOwnerId)
	if dnsOwnerId != "" {
		reconciler.dnsOwnerId = &dnsOwnerId
	}

	renewalWindow, err := c.GetDurationOption(OptRenewalWindow)
	if err != nil {
		return nil, err
	}
	reconciler.renewalWindow = renewalWindow

	return reconciler, nil
}

type certReconciler struct {
	controller.Interface
	reconcile.DefaultReconciler
	targetCluster            cluster.Interface
	dnsCluster               cluster.Interface
	issuerResources          resources.Interface
	issuerSecretResources    resources.Interface
	certResources            resources.Interface
	certSecretResources      resources.Interface
	rateLimiting             time.Duration
	pendingRequests          *legobridge.PendingCertificateRequests
	pendingResults           *legobridge.PendingResults
	defaultIssuer            string
	issuerNamespace          string
	defaultIssuerDomainRange string
	dnsNamespace             *string
	dnsOwnerId               *string
	renewalWindow            time.Duration
	renewalCheckPeriod       time.Duration
}

func (r *certReconciler) Reconcile(logger logger.LogContext, obj resources.Object) reconcile.Status {
	logger.Infof("reconciling")
	crt, ok := obj.Data().(*api.Certificate)
	if !ok {
		return r.failed(logger, obj, api.STATE_ERROR, fmt.Errorf("casting to Certificate failed"))
	}

	if crt.Spec.SecretRef == nil && r.challengePending(crt) {
		return reconcile.Succeeded(logger)
	}

	if result := r.pendingResults.Remove(obj.ObjectName()); result != nil {
		if result.Err != nil {
			return r.failed(logger, obj, api.STATE_ERROR, fmt.Errorf("obtaining certificate failed with %s", result.Err.Error()))
		}

		spec := &api.CertificateSpec{CommonName: result.CommonName, DNSNames: result.DNSNames, CSR: result.CSR}
		specHash := buildSpecHash(spec)
		secretRef, err := r.writeCertificateSecret(obj.ObjectName(), result.Certificates, specHash, crt.Spec.SecretName)
		if err != nil {
			return r.failed(logger, obj, api.STATE_ERROR, fmt.Errorf("writing certificate secret failed with %s", err.Error()))
		}
		logger.Infof("certificate written in secret %s/%s", secretRef.Namespace, secretRef.Name)

		var notAfter *time.Time
		cert, err := legobridge.DecodeCertificate(result.Certificates.Certificate)
		if err == nil {
			notAfter = &cert.NotAfter
		}

		return r.updateSecretRefAndSucceeded(logger, obj, secretRef, specHash, notAfter)
	}

	if crt.Spec.SecretRef == nil {
		if !r.lastPendingRateLimiting(crt.Status.LastPendingTimestamp) {
			return r.obtainCertificateAndPending(logger, obj, nil)
		}
		return reconcile.Delay(logger, fmt.Errorf("waiting"))
	} else {
		specHash := buildSpecHash(&crt.Spec)
		storedHash := crt.Labels[LabelCertificateHashKey]
		if specHash != storedHash {
			return r.deleteSecretRefAndRepeat(logger, obj)
		}

		return r.checkForRenewAndSucceeded(logger, obj)
	}
}

func (r *certReconciler) lastPendingRateLimiting(timestamp *metav1.Time) bool {
	return timestamp != nil && timestamp.Add(r.rateLimiting).After(time.Now())
}

func (r *certReconciler) challengePending(crt *api.Certificate) bool {
	name := resources.NewObjectName(crt.Namespace, crt.Name)
	return r.pendingRequests.Contains(name)
}

func (r *certReconciler) obtainCertificateAndPending(logger logger.LogContext, obj resources.Object, renewSecret *corev1.Secret) reconcile.Status {
	crt := obj.Data().(*api.Certificate)

	reguser, server, err := r.restoreRegUser(crt)
	if err != nil {
		return r.failed(logger, obj, api.STATE_ERROR, err)
	}

	err = r.validatedDomainsAndCsr(&crt.Spec)
	if err != nil {
		return r.failed(logger, obj, api.STATE_ERROR, err)
	}

	specHash := buildSpecHash(&crt.Spec)
	secretRef, notAfter := r.findSecretByHashLabel(specHash)
	if secretRef != nil {
		// reuse found certificate
		secretRef, err := r.copySecretIfNeeded(obj.ObjectName(), secretRef, specHash, crt.Spec.SecretName)
		if err != nil {
			return r.failed(logger, obj, api.STATE_ERROR, err)
		}
		return r.updateSecretRefAndSucceeded(logger, obj, secretRef, specHash, notAfter)
	}

	var renewCert *certificate.Resource
	if renewSecret != nil {
		renewCert = legobridge.SecretDataToCertificates(renewSecret.Data)
	}

	objectName := obj.ObjectName()
	subLogger := logger.NewContext("callback", crt.Name)
	callback := func(output *legobridge.ObtainOutput) {
		r.pendingRequests.Remove(objectName)
		r.pendingResults.Add(objectName, output)
		err := r.EnqueueKey(resources.NewClusterKey(r.targetCluster.GetId(), api.Kind(api.CertificateKind), objectName.Namespace(), objectName.Name()))
		if err != nil {
			subLogger.Warnf("Enqueue %s failed with %s", objectName, err.Error())
		}
	}
	dnsSettings := legobridge.DNSControllerSettings{Namespace: crt.Namespace, OwnerId: r.dnsOwnerId}
	if r.dnsNamespace != nil {
		dnsSettings.Namespace = *r.dnsNamespace
	}
	input := legobridge.ObtainInput{User: reguser, DNSCluster: r.dnsCluster, DNSSettings: dnsSettings,
		CaDirURL: server, CommonName: crt.Spec.CommonName, DNSNames: crt.Spec.DNSNames, CSR: crt.Spec.CSR,
		Callback: callback, RequestName: objectName, RenewCert: renewCert}

	err = legobridge.Obtain(input)
	if err != nil {
		return r.failed(logger, obj, api.STATE_ERROR, fmt.Errorf("preparing obtaining certificates with %s", err.Error()))
	}
	r.pendingRequests.Add(objectName)
	return r.pending(logger, obj)
}

func (r *certReconciler) restoreRegUser(crt *api.Certificate) (*legobridge.RegistrationUser, string, error) {
	// fetch issuer
	issuerName := r.defaultIssuer
	if crt.Spec.IssuerRef != nil {
		issuerName = crt.Spec.IssuerRef.Name
	}
	issuerObjectName := resources.NewObjectName(r.issuerNamespace, issuerName)
	issuer := &api.Issuer{}
	_, err := r.issuerResources.GetInto(issuerObjectName, issuer)
	if err != nil {
		return nil, "", fmt.Errorf("fetching issuer failed with %s", err.Error())
	}

	// fetch issuer secret
	secretRef := issuer.Spec.ACME.PrivateKeySecretRef
	if secretRef == nil {
		return nil, "", fmt.Errorf("missing secret ref in issuer")
	}
	if issuer.Status.State != api.STATE_READY {
		return nil, "", fmt.Errorf("referenced issuer not ready: state=%s", issuer.Status.State)
	}
	issuerSecretObjectName := resources.NewObjectName(secretRef.Namespace, secretRef.Name)
	issuerSecret := &corev1.Secret{}
	_, err = r.issuerSecretResources.GetInto(issuerSecretObjectName, issuerSecret)
	if err != nil {
		return nil, "", fmt.Errorf("fetching issuer secret failed with %s", err.Error())
	}

	reguser, err := legobridge.RegistrationUserFromSecretData(issuerSecret.Data)
	if err != nil {
		return nil, "", fmt.Errorf("restoring registration issuer from issuer secret failed with %s", err.Error())
	}

	return reguser, issuer.Spec.ACME.Server, nil
}

func (r *certReconciler) validatedDomainsAndCsr(spec *api.CertificateSpec) error {
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
	err = r.checkDomainRangeRestriction(spec, domainsToValidate)
	return err
}

func (r *certReconciler) checkDomainRangeRestriction(spec *api.CertificateSpec, domains []string) error {
	issuerName := r.defaultIssuer
	if spec.IssuerRef != nil {
		issuerName = spec.IssuerRef.Name
	}

	if issuerName == r.defaultIssuer && r.defaultIssuerDomainRange != "" {
		for _, domain := range domains {
			if !utils.IsInDomainRange(domain, r.defaultIssuerDomainRange) {
				return fmt.Errorf("domain %s is not in domain range of default issuer (%s)", domain, r.defaultIssuerDomainRange)
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
		return nil, fmt.Errorf("fetching certificate secret failed with %s", err.Error())
	}

	return secret, nil
}

func (r *certReconciler) checkForRenewAndSucceeded(logger logger.LogContext, obj resources.Object) reconcile.Status {
	crt := obj.Data().(*api.Certificate)

	secret, err := r.loadSecret(crt.Spec.SecretRef)
	if err != nil {
		return r.failed(logger, obj, api.STATE_ERROR, err)
	}
	cert, err := legobridge.DecodeCertificateFromSecretData(secret.Data)
	if err != nil {
		return r.failed(logger, obj, api.STATE_ERROR, err)
	}
	logger.Infof("certificate valid from %v to %v", cert.NotBefore, cert.NotAfter)
	if r.needsRenewal(cert) {
		if crt.Status.State == api.STATE_PENDING && r.lastPendingRateLimiting(crt.Status.LastPendingTimestamp) {
			return reconcile.Succeeded(logger)
		}

		// renew certificate
		return r.obtainCertificateAndPending(logger, obj, secret)
	}
	return r.succeeded(logger, obj)
}

func buildSpecHash(spec *api.CertificateSpec) string {
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
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (r *certReconciler) needsRenewal(cert *x509.Certificate) bool {
	return cert.NotAfter.Before(time.Now().Add(r.renewalWindow))
}

func (r *certReconciler) findSecretByHashLabel(specHash string) (*corev1.SecretReference, *time.Time) {
	requirement, err := labels.NewRequirement(LabelCertificateHashKey, selection.Equals, []string{specHash})
	if err != nil {
		return nil, nil
	}
	objs, err := r.certSecretResources.ListCached(labels.NewSelector().Add(*requirement))
	if err != nil {
		return nil, nil
	}

	var best resources.Object
	var bestNotAfter time.Time
	for _, obj := range objs {
		secret := obj.Data().(*corev1.Secret)
		cert, err := legobridge.DecodeCertificateFromSecretData(secret.Data)
		if err != nil {
			continue
		}

		if !r.needsRenewal(cert) {
			if best == nil || bestNotAfter.Before(cert.NotAfter) {
				best = obj
				bestNotAfter = cert.NotAfter
			}
		}
	}
	if best == nil {
		return nil, nil
	}
	ref := &corev1.SecretReference{Namespace: best.GetNamespace(), Name: best.GetName()}
	return ref, &bestNotAfter
}

func (r *certReconciler) copySecretIfNeeded(objectName resources.ObjectName, secretRef *corev1.SecretReference, specHash string, secretName *string) (*corev1.SecretReference, error) {
	if secretName == nil || secretRef.Name == *secretName {
		return secretRef, nil
	}
	secret, err := r.loadSecret(secretRef)
	if err != nil {
		return nil, err
	}
	certificates := legobridge.SecretDataToCertificates(secret.Data)
	return r.writeCertificateSecret(objectName, certificates, specHash, secretName)
}

func (r *certReconciler) writeCertificateSecret(objectName resources.ObjectName, certificates *certificate.Resource,
	specHash string, secretName *string) (*corev1.SecretReference, error) {
	secret := &corev1.Secret{}
	if objectName.Namespace() != "" {
		secret.SetNamespace(objectName.Namespace())
	} else {
		secret.SetNamespace("default")
	}
	if secretName != nil {
		secret.SetName(*secretName)
	} else {
		secret.SetGenerateName(objectName.Name() + "-")
	}
	secret.Labels = map[string]string{LabelCertificateHashKey: specHash, LabelCertificateKey: "true"}
	secret.Data = legobridge.CertificatesToSecretData(certificates)

	obj, err := r.targetCluster.Resources().CreateOrUpdateObject(secret)
	if err != nil {
		return nil, fmt.Errorf("creating/updating certificate secret failed with %s", err.Error())
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
		return r.failed(logger, obj, api.STATE_ERROR, fmt.Errorf("updating certificate resource failed with %s", err.Error()))
	}
	return r.succeeded(logger, obj2)
}

func (r *certReconciler) deleteSecretRefAndRepeat(logger logger.LogContext, obj resources.Object) reconcile.Status {
	c := obj.Data().(*api.Certificate)
	c.Spec.SecretRef = nil
	delete(c.Labels, LabelCertificateHashKey)
	obj2, err := r.certResources.Update(c)
	if err != nil {
		return r.failed(logger, obj, api.STATE_ERROR, fmt.Errorf("updating certificate resource failed with %s", err.Error()))
	}
	return r.repeat(logger, obj2)
}

func (r *certReconciler) prepareUpdateStatus(obj resources.Object, state string, msg *string) (*resources.ModificationState, *api.CertificateStatus) {
	crt := obj.Data().(*api.Certificate)
	status := &crt.Status

	mod := resources.NewModificationState(obj)
	mod.AssureStringPtrPtr(&status.Message, msg)
	mod.AssureStringValue(&status.State, state)
	mod.AssureInt64Value(&status.ObservedGeneration, obj.GetGeneration())

	cn := crt.Spec.CommonName
	dnsNames := crt.Spec.DNSNames
	if crt.Spec.CSR != nil {
		cn, dnsNames, _ = legobridge.ExtractCommonNameAnDNSNames(crt.Spec.CSR)
	}
	mod.AssureStringPtrPtr(&status.CommonName, cn)
	utils.AssureStringArray(&mod.ModificationState, &status.DNSNames, dnsNames)

	var expirationDate *string
	notAfter, ok := resources.GetAnnotation(crt, AnnotationNotAfter)
	if ok {
		expirationDate = &notAfter
	}
	mod.AssureStringPtrPtr(&status.ExpirationDate, expirationDate)

	issuerRef := crt.Spec.IssuerRef
	if issuerRef == nil {
		issuerRef = &api.IssuerRef{r.defaultIssuer}
	}
	if status.IssuerRef == nil || status.IssuerRef.Name != issuerRef.Name {
		status.IssuerRef = issuerRef
		mod.Modify(true)
	}

	return mod, status
}

func updateStatus(mod *resources.ModificationState) {
	err := mod.UpdateStatus()
	if err != nil {
		logger.Warnf("updating status failed with: %s", err)
	}
}

func (r *certReconciler) failed(logger logger.LogContext, obj resources.Object, state string, err error) reconcile.Status {
	msg := err.Error()

	mod, _ := r.prepareUpdateStatus(obj, state, &msg)
	updateStatus(mod)

	return reconcile.Failed(logger, err)
}

func (r *certReconciler) succeeded(logger logger.LogContext, obj resources.Object) reconcile.Status {
	mod, _ := r.prepareUpdateStatus(obj, api.STATE_READY, nil)
	updateStatus(mod)

	return reconcile.Succeeded(logger)
}

func (r *certReconciler) pending(logger logger.LogContext, obj resources.Object) reconcile.Status {
	msg := "certificate requested, preparing/waiting for successful DNS01 challenge"
	mod, status := r.prepareUpdateStatus(obj, api.STATE_PENDING, &msg)
	status.LastPendingTimestamp = &metav1.Time{time.Now()}
	mod.Modified = true
	updateStatus(mod)

	return reconcile.Succeeded(logger)
}

func (r *certReconciler) repeat(logger logger.LogContext, obj resources.Object) reconcile.Status {
	mod, _ := r.prepareUpdateStatus(obj, "", nil)
	updateStatus(mod)

	return reconcile.Repeat(logger)
}

// func (rr *manifest_reconciler) Delete(logger logger.LogContext, obj resources.Object) reconcile.Status {
// 	logger.Infof("Delete")
// 	return reconcile.Succeeded(logger)
// }

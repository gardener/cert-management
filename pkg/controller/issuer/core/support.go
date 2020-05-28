/*
 * Copyright 2019 SAP SE or an SAP affiliate company. All rights reserved. ur file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use ur file except in compliance with the License.
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

package core

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"github.com/gardener/cert-management/pkg/cert/metrics"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sort"
	"strings"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/cert/legobridge"
	"github.com/gardener/cert-management/pkg/cert/utils"
	ctrl "github.com/gardener/cert-management/pkg/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
)

// Enqueuer is an interface to allow enqueue a key
type Enqueuer interface {
	EnqueueKey(key resources.ClusterObjectKey) error
}

// IssuerHandlerFactory is a function type to create an issuer handler
type IssuerHandlerFactory func(support *Support) (IssuerHandler, error)

// IssuerHandler can reconcile issuers.
type IssuerHandler interface {
	Type() string
	CanReconcile(issuer *api.Issuer) bool
	Reconcile(logger logger.LogContext, obj resources.Object, issuer *api.Issuer) reconcile.Status
}

// NewHandlerSupport creates CompoundHandler and Support
func NewHandlerSupport(c controller.Interface, factories ...IssuerHandlerFactory) (*CompoundHandler, *Support, error) {
	defaultCluster := c.GetCluster(ctrl.DefaultCluster)
	targetCluster := c.GetCluster(ctrl.TargetCluster)
	issuerResources, err := defaultCluster.Resources().GetByExample(&api.Issuer{})
	if err != nil {
		return nil, nil, err
	}
	issuerSecretResources, err := defaultCluster.Resources().GetByExample(&corev1.Secret{})
	if err != nil {
		return nil, nil, err
	}

	state := newState()
	s := &Support{
		enqueuer:              c,
		state:                 state,
		issuerResources:       issuerResources,
		issuerSecretResources: issuerSecretResources,
		defaultCluster:        defaultCluster,
		targetCluster:         targetCluster,
	}

	s.defaultIssuerName, _ = c.GetStringOption(OptDefaultIssuer)
	s.issuerNamespace, _ = c.GetStringOption(OptIssuerNamespace)
	domainRangesStr, _ := c.GetStringOption(OptDefaultIssuerDomainRanges)
	if domainRangesStr != "" {
		parts := strings.Split(domainRangesStr, ",")
		for i := range parts {
			parts[i] = utils.NormalizeDomainRange(parts[i])
		}
		s.defaultIssuerDomainRanges = parts
	}

	s.defaultRequestsPerDayQuota, _ = c.GetIntOption(OptDefaultRequestsPerDayQuota)
	if s.defaultRequestsPerDayQuota < 1 {
		return nil, nil, fmt.Errorf("Invalid value for %s: %d", OptDefaultRequestsPerDayQuota, s.defaultRequestsPerDayQuota)
	}

	h := &CompoundHandler{support: s}
	err = h.addIssuerHandlerFactories(factories)
	if err != nil {
		return nil, nil, err
	}

	return h, s, nil
}

// CompoundHandler is an array of IssuerHandler
type CompoundHandler struct {
	support  *Support
	handlers []IssuerHandler
}

// ReconcileIssuer reconciles an issuer and forward it to the correct IssuerHandler
func (h *CompoundHandler) ReconcileIssuer(logger logger.LogContext, obj resources.Object) reconcile.Status {
	logger.Infof("reconciling")
	issuer, ok := obj.Data().(*api.Issuer)
	if !ok {
		return h.failedNoType(logger, obj, api.StateError, fmt.Errorf("casting to issuer failed"))
	}
	if issuer.Namespace != h.support.IssuerNamespace() {
		reconcile.Succeeded(logger)
	}
	for _, handler := range h.handlers {
		if handler.CanReconcile(issuer) {
			return handler.Reconcile(logger, obj, issuer)
		}
	}
	return h.failedNoType(logger, obj, api.StateError, fmt.Errorf("concrete issuer unspecified"))
}

// DeletedIssuer deletes an issuer
func (h *CompoundHandler) DeletedIssuer(logger logger.LogContext, key resources.ClusterObjectKey) reconcile.Status {
	h.support.RemoveIssuer(key.ObjectName())
	logger.Infof("deleted")
	return reconcile.Succeeded(logger)
}

// ReconcileSecret reconciles secrets (for issuers)
func (h *CompoundHandler) ReconcileSecret(logger logger.LogContext, obj resources.Object) reconcile.Status {
	return h.enqueueIssuers(logger, obj.ObjectName())
}

// DeletedSecret updates issuers on deleted secret
func (h *CompoundHandler) DeletedSecret(logger logger.LogContext, key resources.ClusterObjectKey) reconcile.Status {
	return h.enqueueIssuers(logger, key.ObjectName())
}

func (h *CompoundHandler) failedNoType(logger logger.LogContext, obj resources.Object, state string, err error) reconcile.Status {
	return h.support.Failed(logger, obj, state, nil, err)

}

func (h *CompoundHandler) addIssuerHandlerFactories(factories []IssuerHandlerFactory) error {
	for _, factory := range factories {
		handler, err := factory(h.support)
		if err != nil {
			return err
		}
		h.handlers = append(h.handlers, handler)
	}
	return nil
}

func (h *CompoundHandler) enqueueIssuers(logger logger.LogContext, objName resources.ObjectName) reconcile.Status {
	issuers := h.support.IssuerNamesForSecret(objName)
	if issuers != nil {
		groupKind := api.Kind(api.IssuerKind)
		clusterID := h.support.GetDefaultClusterID()
		for issuerName := range issuers {
			key := resources.NewClusterKey(clusterID, groupKind, issuerName.Namespace(), issuerName.Name())
			_ = h.support.EnqueueKey(key)
		}
	}
	return reconcile.Succeeded(logger)
}

// Support provides common issuer/credentials functionality.
type Support struct {
	enqueuer                   Enqueuer
	state                      *state
	defaultCluster             resources.Cluster
	targetCluster              resources.Cluster
	issuerResources            resources.Interface
	issuerSecretResources      resources.Interface
	defaultIssuerName          string
	issuerNamespace            string
	defaultRequestsPerDayQuota int
	defaultIssuerDomainRanges  []string
}

// EnqueueKey forwards to an enqueuer
func (s *Support) EnqueueKey(key resources.ClusterObjectKey) error {
	return s.enqueuer.EnqueueKey(key)
}

// WriteIssuerSecretFromRegistrationUser writes an issuer secret
func (s *Support) WriteIssuerSecretFromRegistrationUser(issuer metav1.ObjectMeta, reguser *legobridge.RegistrationUser,
	secretRef *corev1.SecretReference) (*corev1.SecretReference, *corev1.Secret, error) {
	var err error

	secret := &corev1.Secret{}
	if secretRef != nil && secretRef.Name != "" {
		secret.SetName(secretRef.Name)
		secret.SetNamespace(NormalizeNamespace(secretRef.Namespace))
	} else {
		secret.SetGenerateName(issuer.GetName() + "-")
		secret.SetNamespace(NormalizeNamespace(issuer.GetNamespace()))
	}
	secret.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: api.Version, Kind: api.IssuerKind, Name: issuer.Name, UID: issuer.GetUID()}})
	secret.Data, err = reguser.ToSecretData()
	if err != nil {
		return nil, nil, err
	}

	obj, err := s.defaultCluster.Resources().CreateOrUpdateObject(secret)
	if err != nil {
		return nil, nil, fmt.Errorf("creating/updating issuer secret failed with %s", err.Error())
	}

	return &corev1.SecretReference{Name: obj.GetName(), Namespace: secret.GetNamespace()}, secret, nil
}

// UpdateIssuerSecret updates an issuer secret
func (s *Support) UpdateIssuerSecret(issuer metav1.ObjectMeta, reguser *legobridge.RegistrationUser,
	secret *corev1.Secret) error {
	var err error
	secret.Data, err = reguser.ToSecretData()
	if err != nil {
		return err
	}
	obj, err := s.defaultCluster.Resources().Wrap(secret)
	if err != nil {
		return fmt.Errorf("wrapping issuer secret failed with %s", err.Error())
	}
	err = obj.Update()
	if err != nil {
		return fmt.Errorf("updating issuer secret failed with %s", err.Error())
	}

	return nil
}

// ReadIssuerSecret reads a issuer secret
func (s *Support) ReadIssuerSecret(ref *corev1.SecretReference) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	itf, err := s.defaultCluster.Resources().GetByExample(secret)
	if err != nil {
		return nil, err
	}

	objName := resources.NewObjectName(ref.Namespace, ref.Name)
	_, err = itf.GetInto(objName, secret)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func (s *Support) triggerCertificates(logger logger.LogContext, issuerName resources.ObjectName) {
	array := s.state.CertificateNamesForIssuer(issuerName)
	clusterID := s.targetCluster.GetId()
	if len(array) > 0 {
		logger.Infof("Trigger reconcile for %d certificates of issuer %s", len(array), issuerName)
		for _, objName := range array {
			key := resources.NewClusterKey(clusterID, api.Kind(api.CertificateKind), objName.Namespace(), objName.Name())
			_ = s.enqueuer.EnqueueKey(key)
		}
	}
}

func (s *Support) prepareUpdateStatus(obj resources.Object, state string, itype *string, msg *string) (*resources.ModificationState, *api.IssuerStatus) {
	issuer := obj.Data().(*api.Issuer)
	status := &issuer.Status

	mod := resources.NewModificationState(obj)
	mod.AssureStringPtrPtr(&status.Message, msg)
	mod.AssureStringPtrPtr(&status.Type, itype)
	mod.AssureStringValue(&status.State, state)
	mod.AssureInt64Value(&status.ObservedGeneration, obj.GetGeneration())
	mod.AssureIntValue(&status.RequestsPerDayQuota, s.RememberIssuerQuotas(obj.ObjectName(), issuer.Spec.RequestsPerDayQuota))

	return mod, status
}

func (s *Support) updateStatus(mod *resources.ModificationState) {
	err := mod.UpdateStatus()
	if err != nil {
		logger.Warnf("updating status failed with: %s", err)
	}
}

// Failed handles failed.
func (s *Support) Failed(logger logger.LogContext, obj resources.Object, state string, itype *string, err error) reconcile.Status {
	msg := err.Error()

	mod, _ := s.prepareUpdateStatus(obj, state, itype, &msg)
	s.updateStatus(mod)

	return reconcile.Failed(logger, err)
}

// SucceededAndTriggerCertificates handles succeeded and trigger certificates.
func (s *Support) SucceededAndTriggerCertificates(logger logger.LogContext, obj resources.Object, itype *string, regRaw []byte) reconcile.Status {
	s.triggerCertificates(logger, obj.ObjectName())

	mod, status := s.prepareUpdateStatus(obj, api.StateReady, itype, nil)
	changedRegistration := false
	if status.ACME == nil || status.ACME.Raw == nil {
		changedRegistration = regRaw != nil
	} else {
		changedRegistration = !bytes.Equal(status.ACME.Raw, regRaw)
	}
	if changedRegistration {
		status.ACME = &runtime.RawExtension{Raw: regRaw}
		mod.Modify(true)
	}
	s.updateStatus(mod)

	return reconcile.Succeeded(logger)
}

// AddCertificate adds a certificate
func (s *Support) AddCertificate(logger logger.LogContext, cert *api.Certificate) {
	certObjName, issuerObjName := s.calcAssocObjectNames(cert)
	s.state.AddCertAssoc(issuerObjName, certObjName)
	s.reportCertificateMetrics(issuerObjName)
}

// RemoveCertificate removes a certificate
func (s *Support) RemoveCertificate(logger logger.LogContext, certObjName resources.ObjectName) {
	s.state.RemoveCertAssoc(certObjName)
	s.reportAllCertificateMetrics()
}

func (s *Support) reportCertificateMetrics(issuerObjName resources.ObjectName) {
	count := s.state.CertificateCountForIssuer(issuerObjName)
	metrics.ReportCertEntries("acme", issuerObjName.Name(), count)
}

func (s *Support) reportAllCertificateMetrics() {
	for _, issuerObjName := range s.state.KnownIssuers() {
		s.reportCertificateMetrics(issuerObjName)
	}
}

func (s *Support) calcAssocObjectNames(cert *api.Certificate) (resources.ObjectName, resources.ObjectName) {
	certObjName := newObjectName(cert.Namespace, cert.Name)

	issuerName := s.defaultIssuerName
	if cert.Spec.IssuerRef != nil {
		issuerName = cert.Spec.IssuerRef.Name
	}
	return certObjName, newObjectName(cert.Namespace, issuerName)
}

// NormalizeNamespace returns the namespace or "default" for an empty input.
func NormalizeNamespace(namespace string) string {
	if namespace != "" {
		return namespace
	}
	return "default"
}

func newObjectName(namespace, name string) resources.ObjectName {
	namespace = NormalizeNamespace(namespace)
	return resources.NewObjectName(namespace, name)
}

// DefaultIssuerName returns the default issuer name
func (s *Support) DefaultIssuerName() string {
	return s.defaultIssuerName
}

// IssuerNamespace returns the issuer namespace
func (s *Support) IssuerNamespace() string {
	return s.issuerNamespace
}

// DefaultIssuerDomainRanges returns the default issuer domain ranges.
func (s *Support) DefaultIssuerDomainRanges() []string {
	return s.defaultIssuerDomainRanges
}

// CertificateNamesForIssuer returns the certificate names for an issuer
func (s *Support) CertificateNamesForIssuer(issuer resources.ObjectName) []resources.ObjectName {
	return s.state.CertificateNamesForIssuer(issuer)
}

// IssuerNamesForSecret returns issuer names for a secret name
func (s *Support) IssuerNamesForSecret(secretName resources.ObjectName) resources.ObjectNameSet {
	return s.state.IssuerNamesForSecret(secretName)
}

// RememberIssuerSecret stores issuer secret ref pair.
func (s *Support) RememberIssuerSecret(issuer resources.ObjectName, secretRef *corev1.SecretReference, hash string) {
	s.state.RememberIssuerSecret(issuer, secretRef, hash)
}

// RememberIssuerQuotas stores the issuer quotas.
func (s *Support) RememberIssuerQuotas(issuer resources.ObjectName, issuerRequestsPerDay *int) int {
	requestsPerDay := s.defaultRequestsPerDayQuota
	if issuerRequestsPerDay != nil && *issuerRequestsPerDay > 0 {
		requestsPerDay = *issuerRequestsPerDay
	}
	s.state.RememberIssuerQuotas(issuer, requestsPerDay)
	return requestsPerDay
}

// TryAcceptCertificateRequest tries to accept a certificate request according to the quotas.
// Return true if accepted and the requests per days quota value
func (s *Support) TryAcceptCertificateRequest(issuer resources.ObjectName) (bool, int) {
	return s.state.TryAcceptCertificateRequest(issuer)
}

// GetIssuerSecretHash returns the issuer secret hash code
func (s *Support) GetIssuerSecretHash(issuer resources.ObjectName) string {
	return s.state.GetIssuerSecretHash(issuer)
}

// RemoveIssuer removes an issuer
func (s *Support) RemoveIssuer(name resources.ObjectName) bool {
	b := s.state.RemoveIssuer(name)
	metrics.DeleteCertEntries("acme", name.Name())
	return b
}

// GetDefaultClusterID returns the cluster id of the default cluster
func (s *Support) GetDefaultClusterID() string {
	return s.defaultCluster.GetId()
}

// GetIssuerResources returns the resources for issuer.
func (s *Support) GetIssuerResources() resources.Interface {
	return s.issuerResources
}

// GetIssuerSecretResources returns the resources for issuer secrets.
func (s *Support) GetIssuerSecretResources() resources.Interface {
	return s.issuerSecretResources
}

// CalcSecretHash calculates the secret hash
func (s *Support) CalcSecretHash(secret *corev1.Secret) string {
	if secret == nil {
		return ""
	}
	keys := []string{}
	for k := range secret.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New224()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write(secret.Data[k])
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

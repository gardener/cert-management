/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package core

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/cert/legobridge"
	"github.com/gardener/cert-management/pkg/cert/metrics"
	"github.com/gardener/cert-management/pkg/cert/utils"
	ctrl "github.com/gardener/cert-management/pkg/controller"
)

// RecoverableError is a recoverable error, i.e. reconcile after same backoff may help
type RecoverableError struct {
	Msg      string
	Interval time.Duration
}

func (err *RecoverableError) Error() string {
	return err.Msg
}

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

// NewHandlerSupport creates the shared Support object
func NewHandlerSupport(c controller.Interface) (*Support, error) {
	defaultCluster := c.GetCluster(ctrl.DefaultCluster)
	targetCluster := c.GetCluster(ctrl.TargetCluster)
	defaultIssuerResources, err := defaultCluster.Resources().GetByExample(&api.Issuer{})
	if err != nil {
		return nil, err
	}
	defaultSecretResources, err := defaultCluster.Resources().GetByExample(&corev1.Secret{})
	if err != nil {
		return nil, err
	}

	allowTargetIssuers, _ := c.GetBoolOption(OptAllowTargetIssuers)
	var targetIssuerResources, targetSecretResources resources.Interface
	if allowTargetIssuers {
		targetIssuerResources, err = targetCluster.Resources().GetByExample(&api.Issuer{})
		if err != nil {
			return nil, err
		}
		targetSecretResources, err = targetCluster.Resources().GetByExample(&corev1.Secret{})
		if err != nil {
			return nil, err
		}
	}

	state := newState()
	s := &Support{
		enqueuer:               c,
		state:                  state,
		defaultIssuerResources: defaultIssuerResources,
		defaultSecretResources: defaultSecretResources,
		targetIssuerResources:  targetIssuerResources,
		targetSecretResources:  targetSecretResources,
		targetIssuerAllowed:    allowTargetIssuers,
		defaultCluster:         defaultCluster,
		targetCluster:          targetCluster,
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
		return nil, fmt.Errorf("Invalid value for %s: %d", OptDefaultRequestsPerDayQuota, s.defaultRequestsPerDayQuota)
	}
	return s, err
}

// NewCompoundHandler creates a cluster specific CompoundHandler
func NewCompoundHandler(c controller.Interface, factories ...IssuerHandlerFactory) (*CompoundHandler, error) {
	result := c.GetEnvironment().GetOrCreateSharedValue(c.GetName()+"-support", func() interface{} {
		support, err := NewHandlerSupport(c)
		if err != nil {
			return err
		}
		return support
	})
	if err, ok := result.(error); ok {
		return nil, err
	}
	support := result.(*Support)

	h := &CompoundHandler{support: support}
	err := h.addIssuerHandlerFactories(factories)
	if err != nil {
		return nil, err
	}

	metrics.ReportOverdueCerts(0)

	return h, nil
}

// CompoundHandler is an array of IssuerHandler
type CompoundHandler struct {
	support  *Support
	handlers []IssuerHandler
}

// Support returns the support object
func (h *CompoundHandler) Support() *Support {
	return h.support
}

// ReconcileIssuer reconciles an issuer and forward it to the correct IssuerHandler
func (h *CompoundHandler) ReconcileIssuer(logger logger.LogContext, obj resources.Object) reconcile.Status {
	logger.Infof("reconciling")
	issuer, ok := obj.Data().(*api.Issuer)
	if !ok {
		return h.failedNoType(logger, obj, api.StateError, fmt.Errorf("casting to issuer failed"))
	}
	if h.support.Cluster(obj.ClusterKey()) == utils.ClusterDefault && issuer.Namespace != h.support.IssuerNamespace() {
		logger.Infof("issuer on default cluster ignored as not in issuer namespace %s", h.support.IssuerNamespace())
		return reconcile.Succeeded(logger)
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
	h.support.RemoveIssuer(key)
	logger.Infof("deleted")
	return reconcile.Succeeded(logger)
}

// ReconcileSecret reconciles secrets (for issuers)
func (h *CompoundHandler) ReconcileSecret(logger logger.LogContext, obj resources.Object) reconcile.Status {
	return h.enqueueIssuers(logger, obj.ClusterKey())
}

// DeletedSecret updates issuers on deleted secret
func (h *CompoundHandler) DeletedSecret(logger logger.LogContext, key resources.ClusterObjectKey) reconcile.Status {
	return h.enqueueIssuers(logger, key)
}

func (h *CompoundHandler) failedNoType(logger logger.LogContext, obj resources.Object, state string, err error) reconcile.Status {
	return h.support.Failed(logger, obj, state, nil, err, false)
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

func (h *CompoundHandler) enqueueIssuers(logger logger.LogContext, secretKey resources.ClusterObjectKey) reconcile.Status {
	issuers := h.support.IssuerNamesForSecretOrEABSecret(secretKey)
	if issuers != nil {
		groupKind := api.Kind(api.IssuerKind)
		clusterID := secretKey.Cluster()
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
	defaultIssuerResources     resources.Interface
	defaultSecretResources     resources.Interface
	targetIssuerResources      resources.Interface
	targetSecretResources      resources.Interface
	targetIssuerAllowed        bool
	defaultIssuerName          string
	issuerNamespace            string
	defaultRequestsPerDayQuota int
	defaultIssuerDomainRanges  []string
}

// Cluster returns the cluster enum for the given `ClusterObjectKey`
func (s *Support) Cluster(key resources.ClusterObjectKey) utils.Cluster {
	switch key.Cluster() {
	case s.defaultCluster.GetId():
		return utils.ClusterDefault
	case s.targetCluster.GetId():
		return utils.ClusterTarget
	}
	panic(fmt.Sprintf("unexpected cluster: %s", key.Cluster()))
}

// EnqueueKey forwards to an enqueuer
func (s *Support) EnqueueKey(key resources.ClusterObjectKey) error {
	return s.enqueuer.EnqueueKey(key)
}

// WriteIssuerSecretFromRegistrationUser writes an issuer secret
func (s *Support) WriteIssuerSecretFromRegistrationUser(issuerKey utils.IssuerKey, issuerUID types.UID, reguser *legobridge.RegistrationUser,
	secretRef *corev1.SecretReference,
) (*corev1.SecretReference, *corev1.Secret, error) {
	var err error

	secret := &corev1.Secret{}
	if secretRef != nil && secretRef.Name != "" {
		secret.SetName(secretRef.Name)
		secret.SetNamespace(NormalizeNamespace(secretRef.Namespace))
	} else {
		secret.SetGenerateName(issuerKey.Name() + "-")
		secret.SetNamespace(NormalizeNamespace(issuerKey.Namespace()))
	}
	secret.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: api.Version, Kind: api.IssuerKind, Name: issuerKey.Name(), UID: issuerUID}})
	secret.Data, err = reguser.ToSecretData()
	if err != nil {
		return nil, nil, err
	}

	secretResources, err := s.GetIssuerSecretResources(issuerKey)
	if err != nil {
		return nil, nil, fmt.Errorf("getting issuer secret resources failed: %w", err)
	}
	obj, err := secretResources.CreateOrUpdate(secret)
	if err != nil {
		return nil, nil, fmt.Errorf("creating/updating issuer secret failed: %w", err)
	}

	return &corev1.SecretReference{Name: obj.GetName(), Namespace: secret.GetNamespace()}, secret, nil
}

// UpdateIssuerSecret updates an issuer secret
func (s *Support) UpdateIssuerSecret(issuerKey utils.IssuerKey, reguser *legobridge.RegistrationUser,
	secret *corev1.Secret,
) error {
	var err error
	secret.Data, err = reguser.ToSecretData()
	if err != nil {
		return err
	}
	secretResources, err := s.GetIssuerSecretResources(issuerKey)
	if err != nil {
		return fmt.Errorf("getting issuer secret resources failed: %w", err)
	}
	obj, err := secretResources.Wrap(secret)
	if err != nil {
		return fmt.Errorf("wrapping issuer secret failed: %w", err)
	}
	err = obj.Update()
	if err != nil {
		return fmt.Errorf("updating issuer secret failed: %w", err)
	}

	return nil
}

// ReadIssuerSecret reads a issuer secret
func (s *Support) ReadIssuerSecret(issuerKey utils.IssuerKey, ref *corev1.SecretReference) (*corev1.Secret, error) {
	secretResources, err := s.GetIssuerSecretResources(issuerKey)
	if err != nil {
		return nil, fmt.Errorf("getting issuer secret resources failed: %w", err)
	}

	secret := &corev1.Secret{}
	objName := resources.NewObjectName(ref.Namespace, ref.Name)
	_, err = secretResources.GetInto(objName, secret)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func (s *Support) triggerCertificates(logger logger.LogContext, issuerKey utils.IssuerKey) {
	array := s.state.CertificateNamesForIssuer(issuerKey)
	clusterID := s.targetCluster.GetId()
	if len(array) > 0 {
		logger.Infof("Trigger reconcile for %d certificates of issuer %s", len(array), issuerKey)
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
	mod.AssureIntValue(&status.RequestsPerDayQuota, s.RememberIssuerQuotas(obj.ClusterKey(), issuer.Spec.RequestsPerDayQuota))

	return mod, status
}

func (s *Support) updateStatus(mod *resources.ModificationState) {
	err := mod.UpdateStatus()
	if err != nil {
		logger.Warnf("updating status failed with: %s", err)
	}
}

// Failed handles failed.
func (s *Support) Failed(logger logger.LogContext, obj resources.Object, state string, itype *string, err error, retry bool) reconcile.Status {
	msg := err.Error()

	mod, _ := s.prepareUpdateStatus(obj, state, itype, &msg)
	s.updateStatus(mod)

	if retry {
		return reconcile.Delay(logger, err)
	}
	return reconcile.Failed(logger, err)
}

// SucceededAndTriggerCertificates handles succeeded and trigger certificates.
func (s *Support) SucceededAndTriggerCertificates(logger logger.LogContext, obj resources.Object, itype *string, regRaw []byte) reconcile.Status {
	s.RememberIssuerQuotas(obj.ClusterKey(), obj.Data().(*api.Issuer).Spec.RequestsPerDayQuota)

	s.reportAllCertificateMetrics()
	s.triggerCertificates(logger, s.ToIssuerKey(obj.ClusterKey()))

	mod, status := s.prepareUpdateStatus(obj, api.StateReady, itype, nil)
	if itype != nil {
		switch *itype {
		case ACMEType:
			updateTypeStatus(mod, &status.ACME, regRaw)
		case CAType:
			updateTypeStatus(mod, &status.CA, regRaw)
		}
	}
	s.updateStatus(mod)

	return reconcile.Succeeded(logger)
}

// SucceedSelfSignedIssuer handles succeeded self-signed issuers.
func (s *Support) SucceedSelfSignedIssuer(logger logger.LogContext, obj resources.Object, itype *string) reconcile.Status {
	modificationState, _ := s.prepareUpdateStatus(obj, api.StateReady, itype, nil)
	s.updateStatus(modificationState)
	return reconcile.Succeeded(logger)
}

func updateTypeStatus(mod *resources.ModificationState, status **runtime.RawExtension, regRaw []byte) {
	changedRegistration := false
	if *status == nil || (*status).Raw == nil {
		changedRegistration = regRaw != nil
	} else {
		changedRegistration = !bytes.Equal((*status).Raw, regRaw)
	}
	if changedRegistration {
		*status = &runtime.RawExtension{Raw: regRaw}
		mod.Modify(true)
	}
}

// AddCertificate adds a certificate
func (s *Support) AddCertificate(cert *api.Certificate) {
	certObjName, issuerKey := s.calcAssocObjectNames(cert)
	s.state.AddCertAssoc(issuerKey, certObjName)
	s.reportCertificateExpires(cert.Namespace, cert.Name, cert.Status.ExpirationDate)
	s.reportCertificateMetrics(issuerKey)
}

// RemoveCertificate removes a certificate
func (s *Support) RemoveCertificate(certObjName resources.ObjectName) {
	s.state.RemoveCertAssoc(certObjName)
	s.ClearCertRenewalOverdue(certObjName)
	s.ClearCertRevoked(certObjName)
	s.reportCertificateExpiresRemoved(certObjName.Namespace(), certObjName.Name())
	s.reportAllCertificateMetrics()
}

func (s *Support) reportCertificateMetrics(issuerKey utils.IssuerKey) {
	count := s.state.CertificateCountForIssuer(issuerKey)
	metrics.ReportCertEntries("acme", issuerKey, count)
}

func (s *Support) reportAllCertificateMetrics() {
	for _, key := range s.state.KnownIssuers() {
		s.reportCertificateMetrics(key)
	}
}

func (s *Support) reportCertificateExpires(namespace, name string, expires *string) {
	var seconds int64 = 0
	if expires != nil {
		if expireTime, err := time.Parse(time.RFC3339, *expires); err == nil {
			seconds = expireTime.Unix()
		}
	}
	metrics.ReportCertObjectExpire(namespace, name, seconds)
}

func (s *Support) reportCertificateExpiresRemoved(namespace, name string) {
	metrics.DeleteObjectEntriesExpire(namespace, name)
}

func (s *Support) calcAssocObjectNames(cert *api.Certificate) (resources.ObjectName, utils.IssuerKey) {
	certObjName := newObjectName(cert.Namespace, cert.Name)

	issuerKey := s.IssuerClusterObjectKey(cert.Namespace, &cert.Spec)
	return certObjName, issuerKey
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

// IssuerClusterObjectKey returns either the specified issuer or it tries to find a matching issuer by
// matching domains.
// It tries to find the issuer first on the target cluster, then on the default cluster
func (s *Support) IssuerClusterObjectKey(_ string, spec *api.CertificateSpec) utils.IssuerKey {
	if spec.IssuerRef != nil {
		if spec.IssuerRef.Namespace == "" {
			// it on the default cluster
			return utils.NewDefaultClusterIssuerKey(spec.IssuerRef.Name)
		}
		key := s.FindIssuerKeyByName(spec.IssuerRef.Namespace, spec.IssuerRef.Name)
		if key != nil {
			return *key
		}
		// unknown issue, make reasonable guess
		if spec.IssuerRef.Namespace == s.issuerNamespace {
			return utils.NewDefaultClusterIssuerKey(spec.IssuerRef.Name)
		}
		return utils.NewIssuerKey(utils.ClusterTarget, spec.IssuerRef.Namespace, spec.IssuerRef.Name)
	}

	domains, err := utils.ExtractDomains(spec)
	if err == nil {
		key := s.FindIssuerKeyByBestMatch(domains)
		if key != nil {
			return *key
		}
	}
	return utils.NewDefaultClusterIssuerKey(s.defaultIssuerName)
}

// FindIssuerKeyByName tries to find an issuer key on target or default cluster
func (s *Support) FindIssuerKeyByName(namespace, issuerName string) *utils.IssuerKey {
	var bestKey *utils.IssuerKey
	var bestFit int
	for _, key := range s.state.KnownIssuers() {
		if key.Name() == issuerName {
			fit := 1
			if key.Cluster() == utils.ClusterTarget {
				fit++
				if key.Namespace() == namespace {
					fit++
				}
			}
			if fit > bestFit {
				k := key
				bestKey = &k
				bestFit = fit
			}
		}
	}
	return bestKey
}

// FindIssuerKeyByBestMatch tries to find the best matching issuer with respect to the DNS selection
func (s *Support) FindIssuerKeyByBestMatch(domains []string) *utils.IssuerKey {
	var bestKey *utils.IssuerKey
	var bestFit int
	for key, sel := range s.state.GetAllIssuerDomains() {
		fit := 0
		if sel != nil {
			for _, domain := range domains {
				if len(sel.Exclude) > 0 && utils.IsInDomainRanges(domain, sel.Exclude) {
					continue
				}
				best := utils.BestDomainRange(domain, sel.Include)
				if len(best) > 0 {
					fit += 1000
					fit += len(best)
				}
			}
		} else if s.IsDefaultIssuer(key) {
			fit = 1
			if s.DefaultIssuerDomainRanges() != nil {
				ranges := s.DefaultIssuerDomainRanges()
				for _, domain := range domains {
					best := utils.BestDomainRange(domain, ranges)
					if len(best) > 0 {
						fit += 900
						fit += len(best)
					}
				}
			}
		}
		if fit > bestFit {
			k := key
			bestKey = &k
			bestFit = fit
		}
	}
	return bestKey
}

// DefaultIssuerDomainRanges returns the default issuer domain ranges.
func (s *Support) DefaultIssuerDomainRanges() []string {
	return s.defaultIssuerDomainRanges
}

// CertificateNamesForIssuer returns the certificate names for an issuer
func (s *Support) CertificateNamesForIssuer(issuer resources.ClusterObjectKey) []resources.ObjectName {
	issuerKey := s.ToIssuerKey(issuer)
	return s.state.CertificateNamesForIssuer(issuerKey)
}

// IssuerNamesForSecretOrEABSecret returns issuer names for a secret name
func (s *Support) IssuerNamesForSecretOrEABSecret(secretKey resources.ClusterObjectKey) resources.ObjectNameSet {
	cluster := utils.ClusterTarget
	if secretKey.Cluster() == s.defaultCluster.GetId() {
		cluster = utils.ClusterDefault
	}
	key := utils.NewIssuerSecretKey(cluster, secretKey.Namespace(), secretKey.Name())
	list1 := s.toObjectNameSet(s.state.IssuerNamesForSecret(key))
	list2 := s.toObjectNameSet(s.state.IssuerNamesForEABSecret(key))
	if list1 != nil {
		if list2 != nil {
			return list1.AddSet(list2)
		}
		return list1
	}
	return list2
}

// RememberIssuerSecret stores issuer secret ref pair.
func (s *Support) RememberIssuerSecret(issuer resources.ClusterObjectKey, secretRef *corev1.SecretReference, hash string) {
	issuerKey := s.ToIssuerKey(issuer)
	s.state.RememberIssuerSecret(issuerKey, secretRef, hash)
}

// RememberAltIssuerSecret stores issuer secret ref pair for migration from v0.7.x
// This method is only needed for a bugfix for migrating v0.7.x to v0.8.x an can be deleted after v0.9.0
func (s *Support) RememberAltIssuerSecret(issuer resources.ClusterObjectKey, secretRef *corev1.SecretReference, secret *corev1.Secret, email string) {
	if secret == nil || secret.Data == nil {
		return
	}
	if _, ok := secret.Data[legobridge.KeyPrivateKey]; !ok {
		return
	}

	issuerKey := s.ToIssuerKey(issuer)
	s2 := &corev1.Secret{
		Data: map[string][]byte{},
	}
	if _, ok := secret.Data["email"]; ok {
		// drop email
		s2.Data[legobridge.KeyPrivateKey] = []byte(strings.TrimSpace(string(secret.Data[legobridge.KeyPrivateKey])) + "\n")
	} else {
		// add email
		s2.Data[legobridge.KeyPrivateKey] = []byte(strings.TrimSpace(string(secret.Data[legobridge.KeyPrivateKey])))
		s2.Data["email"] = []byte(email)
	}
	altHash := s.CalcSecretHash(s2)
	s.state.RememberAltIssuerSecret(issuerKey, secretRef, altHash)
}

// RememberIssuerEABSecret stores issuer EAB secret ref pair.
func (s *Support) RememberIssuerEABSecret(issuer resources.ClusterObjectKey, secretRef *corev1.SecretReference, hash string) {
	issuerKey := s.ToIssuerKey(issuer)
	s.state.RememberIssuerEABSecret(issuerKey, secretRef, hash)
}

// RememberIssuerQuotas stores the issuer quotas.
func (s *Support) RememberIssuerQuotas(issuer resources.ClusterObjectKey, issuerRequestsPerDay *int) int {
	issuerKey := s.ToIssuerKey(issuer)
	requestsPerDay := s.defaultRequestsPerDayQuota
	if issuerRequestsPerDay != nil && *issuerRequestsPerDay > 0 {
		requestsPerDay = *issuerRequestsPerDay
	}
	s.state.RememberIssuerQuotas(issuerKey, requestsPerDay)
	return requestsPerDay
}

// TryAcceptCertificateRequest tries to accept a certificate request according to the quotas.
// Return true if accepted and the requests per days quota value
func (s *Support) TryAcceptCertificateRequest(issuer utils.IssuerKey) (bool, int) {
	return s.state.TryAcceptCertificateRequest(issuer)
}

// GetIssuerSecretHash returns the issuer secret hash code
func (s *Support) GetIssuerSecretHash(issuer utils.IssuerKey) string {
	return s.state.GetIssuerSecretHash(issuer)
}

// GetAltIssuerSecretHash returns the issuer alternative secret hash code
// This method is only needed for a bugfix for migrating v0.7.x to v0.8.x an can be deleted after v0.9.0
func (s *Support) GetAltIssuerSecretHash(issuer utils.IssuerKey) string {
	return s.state.GetAltIssuerSecretHash(issuer)
}

// RemoveIssuer removes an issuer
func (s *Support) RemoveIssuer(issuer resources.ClusterObjectKey) bool {
	issuerKey := s.ToIssuerKey(issuer)
	b := s.state.RemoveIssuer(issuerKey)
	metrics.DeleteCertEntries("acme", issuerKey)
	return b
}

// IsDefaultIssuer returns true if the issuer key is the default issuer
func (s *Support) IsDefaultIssuer(issuerKey utils.IssuerKey) bool {
	return issuerKey.Name() == s.defaultIssuerName && issuerKey.Cluster() == utils.ClusterDefault
}

// GetIssuerResources returns the resources for issuer.
func (s *Support) GetIssuerResources(issuerKey utils.IssuerKey) (resources.Interface, error) {
	switch issuerKey.Cluster() {
	case utils.ClusterDefault:
		return s.defaultIssuerResources, nil
	case utils.ClusterTarget:
		if !s.targetIssuerAllowed {
			return nil, fmt.Errorf("target issuers not allowed")
		}
		return s.targetIssuerResources, nil
	}
	return nil, fmt.Errorf("unexpected issuer cluster: %s", issuerKey.ClusterName())
}

// GetIssuerSecretResources returns the resources for issuer secrets.
func (s *Support) GetIssuerSecretResources(issuerKey utils.IssuerKey) (resources.Interface, error) {
	switch issuerKey.Cluster() {
	case utils.ClusterDefault:
		return s.defaultSecretResources, nil
	case utils.ClusterTarget:
		if !s.targetIssuerAllowed {
			return nil, fmt.Errorf("target issuers not allowed")
		}
		return s.targetSecretResources, nil
	}
	return nil, fmt.Errorf("unexpected issuer cluster: %s", issuerKey.ClusterName())
}

// CalcSecretHash calculates the secret hash
// If real is true, precalculated hash value of `IssuerSecretHashKey` is ignored
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

// SetCertRenewalOverdue sets a certificate object as renewal overdue
func (s *Support) SetCertRenewalOverdue(certName resources.ObjectName) {
	if s.state.AddRenewalOverdue(certName) {
		s.reportRenewalOverdueCount()
	}
}

// ClearCertRenewalOverdue clears a certificate object as renewal overdue
func (s *Support) ClearCertRenewalOverdue(certName resources.ObjectName) {
	if s.state.RemoveRenewalOverdue(certName) {
		s.reportRenewalOverdueCount()
	}
}

// GetAllRenewalOverdue gets all certificate object object names which are renewal overdue
func (s *Support) GetAllRenewalOverdue() []resources.ObjectName {
	return s.state.GetAllRenewalOverdue()
}

func (s *Support) reportRenewalOverdueCount() {
	count := s.state.GetRenewalOverdueCount()
	metrics.ReportOverdueCerts(count)
}

// SetCertRevoked sets a certificate object as revoked
func (s *Support) SetCertRevoked(certName resources.ObjectName) {
	if s.state.AddRevoked(certName) {
		s.reportRevokedCount()
	}
}

// ClearCertRevoked clears a certificate object as revoked
func (s *Support) ClearCertRevoked(certName resources.ObjectName) {
	if s.state.RemoveRevoked(certName) {
		s.reportRevokedCount()
	}
}

// GetAllRevoked gets all certificate object names which are revoked
func (s *Support) GetAllRevoked() []resources.ObjectName {
	return s.state.GetAllRevoked()
}

func (s *Support) reportRevokedCount() {
	count := s.state.GetRevokedCount()
	metrics.ReportRevokedCerts(count)
}

// LoadIssuer loads the issuer for the given Certificate
func (s *Support) LoadIssuer(issuerKey utils.IssuerKey) (*api.Issuer, error) {
	issuerResources, err := s.GetIssuerResources(issuerKey)
	if err != nil {
		return nil, err
	}
	issuer := &api.Issuer{}
	_, err = issuerResources.GetInto(issuerKey.ObjectName(s.IssuerNamespace()), issuer)
	if err != nil {
		return nil, fmt.Errorf("fetching issuer failed: %w", err)
	}
	return issuer, nil
}

// RestoreRegUser restores a legobridge user from an issuer
func (s *Support) RestoreRegUser(issuerKey utils.IssuerKey, issuer *api.Issuer) (*legobridge.RegistrationUser, error) {
	acme := issuer.Spec.ACME

	if acme == nil {
		return nil, fmt.Errorf("not an ACME issuer")
	}

	// fetch issuer secret
	secretRef := acme.PrivateKeySecretRef
	if secretRef == nil {
		return nil, fmt.Errorf("missing secret ref in issuer")
	}
	if issuer.Status.State != api.StateReady {
		if issuer.Status.State != api.StateError {
			return nil, &RecoverableError{Msg: fmt.Sprintf("referenced issuer not ready: state=%s", issuer.Status.State)}
		}
		return nil, fmt.Errorf("referenced issuer not ready: state=%s", issuer.Status.State)
	}
	if issuer.Status.ACME == nil || issuer.Status.ACME.Raw == nil {
		return nil, fmt.Errorf("ACME registration missing in status")
	}
	issuerSecret, err := s.ReadIssuerSecret(issuerKey, secretRef)
	if err != nil {
		return nil, fmt.Errorf("fetching issuer secret failed: %w", err)
	}

	eabKeyID, eabHmacKey, err := s.LoadEABHmacKey(nil, issuerKey, acme)
	if err != nil {
		return nil, err
	}

	reguser, err := legobridge.RegistrationUserFromSecretData(issuerKey, issuer.Spec.ACME.Email, issuer.Spec.ACME.Server,
		issuer.Status.ACME.Raw, issuerSecret.Data, eabKeyID, eabHmacKey)
	if err != nil {
		return nil, fmt.Errorf("restoring registration issuer from issuer secret failed: %w", err)
	}

	return reguser, nil
}

// LoadEABHmacKey reads the external account binding MAC key from the referenced secret
func (s *Support) LoadEABHmacKey(objKey *resources.ClusterObjectKey, issuerKey utils.IssuerKey, acme *api.ACMESpec) (string, string, error) {
	eab := acme.ExternalAccountBinding
	if eab == nil {
		return "", "", nil
	}

	if eab.KeyID == "" {
		return "", "", fmt.Errorf("missing keyID for external account binding in ACME spec")
	}

	if eab.KeySecretRef == nil {
		return "", "", fmt.Errorf("missing secret ref in issuer for external account binding")
	}

	secret, err := s.ReadIssuerSecret(issuerKey, eab.KeySecretRef)
	if err != nil {
		return "", "", fmt.Errorf("fetching issuer EAB secret failed: %w", err)
	}
	if objKey != nil {
		hash := s.CalcSecretHash(secret)
		s.RememberIssuerEABSecret(*objKey, eab.KeySecretRef, hash)
	}

	hmacEncoded, ok := secret.Data[legobridge.KeyHmacKey]
	if !ok {
		return "", "", fmt.Errorf("Key %s not found in EAB secret %s/%s", legobridge.KeyHmacKey,
			eab.KeySecretRef.Namespace, eab.KeySecretRef.Name)
	}

	return eab.KeyID, string(hmacEncoded), nil
}

// ToIssuerKey creates issuer key from issuer name
func (s *Support) ToIssuerKey(issuer resources.ClusterObjectKey) utils.IssuerKey {
	if issuer.Cluster() == s.defaultCluster.GetId() {
		return utils.NewDefaultClusterIssuerKey(issuer.Name())
	}
	return utils.NewIssuerKey(utils.ClusterTarget, issuer.Namespace(), issuer.Name())
}

// AddIssuerDomains remembers the DNS selection for an ACME issuer
func (s *Support) AddIssuerDomains(issuer resources.ClusterObjectKey, sel *api.DNSSelection) {
	s.state.AddIssuerDomains(s.ToIssuerKey(issuer), sel)
}

func (s *Support) toObjectNameSet(keyset utils.IssuerKeySet) resources.ObjectNameSet {
	if keyset == nil {
		return nil
	}
	nameset := resources.NewObjectNameSet()
	for key := range keyset {
		namespace := key.Namespace()
		if key.Cluster() == utils.ClusterDefault {
			namespace = s.IssuerNamespace()
		}
		nameset.Add(resources.NewObjectName(namespace, key.Name()))
	}
	return nameset
}

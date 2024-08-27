/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package core

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/cert-management/pkg/cert/legobridge"
	"github.com/gardener/cert-management/pkg/cert/metrics"
	"github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
)

// RecoverableError is a recoverable error, i.e. reconcile after same backoff may help
type RecoverableError struct {
	Msg      string
	Interval time.Duration
}

func (err *RecoverableError) Error() string {
	return err.Msg
}

// IssuerHandlerFactory is a function type to create an issuer handler
type IssuerHandlerFactory func(support *Support) (IssuerHandler, error)

// IssuerHandler can reconcile issuers.
type IssuerHandler interface {
	Type() string
	CanReconcile(issuer *v1alpha1.Issuer) bool
	Reconcile(ctx context.Context, log logr.Logger, issuer *v1alpha1.Issuer) (reconcile.Result, error)
	Delete(ctx context.Context, log logr.Logger, issuer *v1alpha1.Issuer) (reconcile.Result, error)
}

// NewHandlerSupport creates the shared Support object
func NewHandlerSupport(defaultIssuerName string, issuerNamespace string, defaultRequestsPerDayQuota int) (*Support, error) {
	state := newState()
	s := &Support{
		state:                      state,
		defaultRequestsPerDayQuota: defaultRequestsPerDayQuota,
		issuerNamespace:            issuerNamespace,
		defaultIssuer: NewIssuerKey(client.ObjectKey{
			Namespace: issuerNamespace,
			Name:      defaultIssuerName,
		}, true),
	}
	return s, nil
}

// Support provides common issuer/credentials functionality.
type Support struct {
	state                      *state
	defaultRequestsPerDayQuota int
	issuerNamespace            string
	defaultIssuer              IssuerKey
}

// AddCertificate adds a certificate
func (s *Support) AddCertificate(cert *v1alpha1.Certificate) {
	certObjName, issuerKey := s.calcAssocObjectNames(cert)
	s.state.AddCertAssoc(issuerKey, certObjName)
	s.reportCertificateExpires(cert.Namespace, cert.Name, cert.Status.ExpirationDate)
	s.reportCertificateMetrics(issuerKey)
}

// RemoveCertificate removes a certificate
func (s *Support) RemoveCertificate(certObjName client.ObjectKey) {
	s.state.RemoveCertAssoc(certObjName)
	s.ClearCertRenewalOverdue(certObjName)
	s.ClearCertRevoked(certObjName)
	s.reportCertificateExpiresRemoved(certObjName.Namespace, certObjName.Name)
	s.reportAllCertificateMetrics()
}

func (s *Support) reportCertificateMetrics(issuerKey IssuerKey) {
	count := s.state.CertificateCountForIssuer(issuerKey)
	_ = count
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

func (s *Support) calcAssocObjectNames(cert *v1alpha1.Certificate) (client.ObjectKey, IssuerKey) {
	issuerKey := s.IssuerKeyFromCertSpec(&cert.Spec)
	return client.ObjectKeyFromObject(cert), issuerKey
}

// IssuerKeyFromCertSpec returns either the specified issuer or it tries to find a matching issuer by
// matching domains.
// It tries to find the issuer first on the target cluster, then on the default cluster
func (s *Support) IssuerKeyFromCertSpec(spec *v1alpha1.CertificateSpec) IssuerKey {
	if spec.IssuerRef == nil {
		return s.defaultIssuer
	}

	key := s.FindIssuerKeyByName(spec.IssuerRef.Namespace, spec.IssuerRef.Name)
	if key != nil {
		return *key
	}

	// unknown issuer, make reasonable guess
	if spec.IssuerRef.Namespace == "" || spec.IssuerRef.Namespace == s.issuerNamespace {
		// it is on the secondary cluster
		return NewIssuerKey(client.ObjectKey{Namespace: s.issuerNamespace, Name: spec.IssuerRef.Name}, true)
	}
	return NewIssuerKey(client.ObjectKey{Namespace: spec.IssuerRef.Namespace, Name: spec.IssuerRef.Name}, false)
}

// FindIssuerKeyByName tries to find an issuer key on target or default cluster
func (s *Support) FindIssuerKeyByName(namespace, issuerName string) *IssuerKey {
	var bestKey *IssuerKey
	var bestFit int
	for _, key := range s.state.KnownIssuers() {
		if key.ObjectKey.Name == issuerName {
			fit := -1
			if key.Secondary() {
				fit = 1
			} else if key.ObjectKey.Namespace == namespace {
				fit = 2
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

// CertificateNamesForIssuer returns the certificate names for an issuer
func (s *Support) CertificateNamesForIssuer(key IssuerKey) []client.ObjectKey {
	return s.state.CertificateNamesForIssuer(key)
}

// IssuerNamesForSecretOrEABSecret returns issuer names for a secret name
func (s *Support) IssuerNamesForSecretOrEABSecret(key SecretKey) sets.Set[IssuerKey] {
	set1 := s.state.IssuerNamesForSecret(key)
	set2 := s.state.IssuerNamesForEABSecret(key)
	if set1 != nil {
		if set2 != nil {
			return set1.Union(set2)
		}
		return set1
	}
	return set2
}

// RememberIssuerSecret stores issuer secret ref pair.
func (s *Support) RememberIssuerSecret(issuerKey IssuerKey, secretRef *corev1.SecretReference, hash string) {
	s.state.RememberIssuerSecret(issuerKey, secretRef, hash)
}

// RememberIssuerEABSecret stores issuer EAB secret ref pair.
func (s *Support) RememberIssuerEABSecret(issuerKey IssuerKey, secretRef *corev1.SecretReference, hash string) {
	s.state.RememberIssuerEABSecret(issuerKey, secretRef, hash)
}

// RememberIssuerQuotas stores the issuer quotas.
func (s *Support) RememberIssuerQuotas(issuerKey IssuerKey, issuerRequestsPerDay *int) int {
	requestsPerDay := s.defaultRequestsPerDayQuota
	if issuerRequestsPerDay != nil && *issuerRequestsPerDay > 0 {
		requestsPerDay = *issuerRequestsPerDay
	}
	s.state.RememberIssuerQuotas(issuerKey, requestsPerDay)
	return requestsPerDay
}

// TryAcceptCertificateRequest tries to accept a certificate request according to the quotas.
// Return true if accepted and the requests per days quota value
func (s *Support) TryAcceptCertificateRequest(issuer IssuerKey) (bool, int) {
	return s.state.TryAcceptCertificateRequest(issuer)
}

// GetIssuerSecretHash returns the issuer secret hash code
func (s *Support) GetIssuerSecretHash(issuer IssuerKey) string {
	return s.state.GetIssuerSecretHash(issuer)
}

// RemoveIssuer removes an issuer
func (s *Support) RemoveIssuer(issuerKey IssuerKey) bool {
	b := s.state.RemoveIssuer(issuerKey)
	metrics.DeleteCertEntries("acme", issuerKey)
	return b
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

// LoadEABHmacKey reads the external account binding MAC key from the referenced secret
func (s *Support) LoadEABHmacKey(ctx context.Context, client client.Client, issuerKey IssuerKey, acme *v1alpha1.ACMESpec) (string, string, error) {
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

	secret := &corev1.Secret{}
	if err := client.Get(ctx, ObjectKeyFromSecretReference(eab.KeySecretRef), secret); err != nil {
		return "", "", fmt.Errorf("fetching issuer EAB secret failed: %w", err)
	}
	hash := s.CalcSecretHash(secret)
	s.RememberIssuerEABSecret(issuerKey, eab.KeySecretRef, hash)

	hmacEncoded, ok := secret.Data[legobridge.KeyHmacKey]
	if !ok {
		return "", "", fmt.Errorf("Key %s not found in EAB secret %s/%s", legobridge.KeyHmacKey,
			eab.KeySecretRef.Namespace, eab.KeySecretRef.Name)
	}

	return eab.KeyID, string(hmacEncoded), nil
}

// SetCertRenewalOverdue sets a certificate object as renewal overdue
func (s *Support) SetCertRenewalOverdue(certName client.ObjectKey) {
	if s.state.AddRenewalOverdue(certName) {
		s.reportRenewalOverdueCount()
	}
}

// ClearCertRenewalOverdue clears a certificate object as renewal overdue
func (s *Support) ClearCertRenewalOverdue(certName client.ObjectKey) {
	if s.state.RemoveRenewalOverdue(certName) {
		s.reportRenewalOverdueCount()
	}
}

// GetAllRenewalOverdue gets all certificate object object names which are renewal overdue
func (s *Support) GetAllRenewalOverdue() []client.ObjectKey {
	return s.state.GetAllRenewalOverdue()
}

func (s *Support) reportRenewalOverdueCount() {
	count := s.state.GetRenewalOverdueCount()
	metrics.ReportOverdueCerts(count)
}

// SetCertRevoked sets a certificate object as revoked
func (s *Support) SetCertRevoked(certName client.ObjectKey) {
	if s.state.AddRevoked(certName) {
		s.reportRevokedCount()
	}
}

// ClearCertRevoked clears a certificate object as revoked
func (s *Support) ClearCertRevoked(certName client.ObjectKey) {
	if s.state.RemoveRevoked(certName) {
		s.reportRevokedCount()
	}
}

// GetAllRevoked gets all certificate object keys which are revoked
func (s *Support) GetAllRevoked() []client.ObjectKey {
	return s.state.GetAllRevoked()
}

func (s *Support) reportRevokedCount() {
	count := s.state.GetRevokedCount()
	metrics.ReportRevokedCerts(count)
}

// AddIssuerDomains remembers the DNS selection for an ACME issuer
func (s *Support) AddIssuerDomains(issuerKey IssuerKey, sel *v1alpha1.DNSSelection) {
	s.state.AddIssuerDomains(issuerKey, sel)
}

// NormalizeNamespace returns the namespace or "default" for an empty input.
func NormalizeNamespace(namespace string) string {
	if namespace != "" {
		return namespace
	}
	return "default"
}

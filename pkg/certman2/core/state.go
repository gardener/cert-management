/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package core

import (
	"github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type state struct {
	secrets      ReferencedSecrets
	altSecrets   ReferencedSecrets
	eabSecrets   ReferencedSecrets
	certificates AssociatedObjects
	quotas       Quotas
	selections   IssuerDNSSelections
	overdueCerts objectKeySet
	revokedCerts objectKeySet
}

func newState() *state {
	return &state{secrets: *NewReferencedSecrets(), altSecrets: *NewReferencedSecrets(), eabSecrets: *NewReferencedSecrets(),
		certificates: *NewAssociatedObjects(), quotas: *NewQuotas(),
		selections:   *NewIssuerDNSSelections(),
		overdueCerts: *newObjectKeySet(), revokedCerts: *newObjectKeySet()}
}

func (s *state) AddIssuerDomains(key IssuerKey, sel *v1alpha1.DNSSelection) {
	s.selections.Add(key, sel)
}

func (s *state) GetAllIssuerDomains() map[IssuerKey]*v1alpha1.DNSSelection {
	return s.selections.GetAll()
}

func (s *state) RemoveIssuer(key IssuerKey) bool {
	s.certificates.RemoveByIssuer(key)
	s.quotas.RemoveIssuer(key)
	s.eabSecrets.RemoveIssuer(key)
	s.altSecrets.RemoveIssuer(key)
	s.selections.Remove(key)
	return s.secrets.RemoveIssuer(key)
}

func (s *state) AddCertAssoc(issuer IssuerKey, cert client.ObjectKey) {
	s.certificates.AddAssoc(issuer, cert)
}

func (s *state) RemoveCertAssoc(cert client.ObjectKey) {
	s.certificates.RemoveByCertificate(cert)
}

func (s *state) CertificateNamesForIssuer(issuer IssuerKey) []client.ObjectKey {
	return s.certificates.Certificates(issuer)
}

func (s *state) CertificateCountForIssuer(issuer IssuerKey) int {
	return s.certificates.CertificateCount(issuer)
}

func (s *state) KnownIssuers() []IssuerKey {
	return s.selections.Issuers()
}

func (s *state) RememberIssuerQuotas(issuer IssuerKey, requestsPerDay int) {
	s.quotas.RememberQuotas(issuer, requestsPerDay)
}

// TryAcceptCertificateRequest tries to accept a certificate request according to the quotas.
// Return true if accepted and the requests per days quota value
func (s *state) TryAcceptCertificateRequest(issuer IssuerKey) (bool, int) {
	return s.quotas.TryAccept(issuer)
}

func (s *state) IssuerNamesForSecret(secretKey SecretKey) sets.Set[IssuerKey] {
	return s.secrets.IssuerNamesFor(secretKey)
}

func (s *state) RememberIssuerSecret(issuer IssuerKey, secretRef *v1.SecretReference, hash string) {
	s.secrets.RememberIssuerSecret(issuer, secretRef, hash)
}

func (s *state) GetIssuerSecretHash(issuerKey IssuerKey) string {
	return s.secrets.GetIssuerSecretHash(issuerKey)
}

// RememberAltIssuerSecret for migration
// This method is only needed for a bugfix for migrating v0.7.x to v0.8.x an can be deleted after v0.9.0
func (s *state) RememberAltIssuerSecret(issuer IssuerKey, secretRef *v1.SecretReference, hash string) {
	s.altSecrets.RememberIssuerSecret(issuer, secretRef, hash)
}

// GetAltIssuerSecretHash for migration
// This method is only needed for a bugfix for migrating v0.7.x to v0.8.x an can be deleted after v0.9.0
func (s *state) GetAltIssuerSecretHash(issuerKey IssuerKey) string {
	return s.altSecrets.GetIssuerSecretHash(issuerKey)
}

func (s *state) IssuerNamesForEABSecret(secretKey SecretKey) sets.Set[IssuerKey] {
	return s.eabSecrets.IssuerNamesFor(secretKey)
}

func (s *state) RememberIssuerEABSecret(issuer IssuerKey, secretRef *v1.SecretReference, hash string) {
	s.eabSecrets.RememberIssuerSecret(issuer, secretRef, hash)
}

func (s *state) AddRenewalOverdue(certName client.ObjectKey) bool {
	return s.overdueCerts.Add(certName)
}

func (s *state) RemoveRenewalOverdue(certName client.ObjectKey) bool {
	return s.overdueCerts.Remove(certName)
}

func (s *state) GetAllRenewalOverdue() []client.ObjectKey {
	return s.overdueCerts.UnsortedList()
}

func (s *state) GetRenewalOverdueCount() int {
	return s.overdueCerts.Size()
}

func (s *state) AddRevoked(certName client.ObjectKey) bool {
	return s.revokedCerts.Add(certName)
}

func (s *state) RemoveRevoked(certName client.ObjectKey) bool {
	return s.revokedCerts.Remove(certName)
}

func (s *state) GetAllRevoked() []client.ObjectKey {
	return s.revokedCerts.UnsortedList()
}

func (s *state) GetRevokedCount() int {
	return s.revokedCerts.Size()
}

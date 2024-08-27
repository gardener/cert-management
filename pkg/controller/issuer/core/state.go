/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package core

import (
	"github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/cert/utils"
	"github.com/gardener/controller-manager-library/pkg/resources"
	v1 "k8s.io/api/core/v1"
)

type state struct {
	secrets      ReferencedSecrets
	altSecrets   ReferencedSecrets
	eabSecrets   ReferencedSecrets
	certificates AssociatedObjects
	quotas       Quotas
	selections   IssuerDNSSelections
	overdueCerts objectNameSet
	revokedCerts objectNameSet
}

func newState() *state {
	return &state{
		secrets: *NewReferencedSecrets(), altSecrets: *NewReferencedSecrets(), eabSecrets: *NewReferencedSecrets(),
		certificates: *NewAssociatedObjects(), quotas: *NewQuotas(),
		selections:   *NewIssuerDNSSelections(),
		overdueCerts: *newObjectNameSet(), revokedCerts: *newObjectNameSet(),
	}
}

func (s *state) AddIssuerDomains(key utils.IssuerKey, sel *v1alpha1.DNSSelection) {
	s.selections.Add(key, sel)
}

func (s *state) GetAllIssuerDomains() map[utils.IssuerKey]*v1alpha1.DNSSelection {
	return s.selections.GetAll()
}

func (s *state) RemoveIssuer(key utils.IssuerKey) bool {
	s.certificates.RemoveBySource(key)
	s.quotas.RemoveIssuer(key)
	s.eabSecrets.RemoveIssuer(key)
	s.altSecrets.RemoveIssuer(key)
	s.selections.Remove(key)
	return s.secrets.RemoveIssuer(key)
}

func (s *state) AddCertAssoc(issuer utils.IssuerKey, cert resources.ObjectName) {
	s.certificates.AddAssoc(issuer, cert)
}

func (s *state) RemoveCertAssoc(cert resources.ObjectName) {
	s.certificates.RemoveByDest(cert)
}

func (s *state) CertificateNamesForIssuer(issuer utils.IssuerKey) []resources.ObjectName {
	return s.certificates.DestinationsAsArray(issuer)
}

func (s *state) CertificateCountForIssuer(issuer utils.IssuerKey) int {
	return s.certificates.DestinationsCount(issuer)
}

func (s *state) KnownIssuers() []utils.IssuerKey {
	return s.selections.Issuers()
}

func (s *state) RememberIssuerQuotas(issuer utils.IssuerKey, requestsPerDay int) {
	s.quotas.RememberQuotas(issuer, requestsPerDay)
}

// TryAcceptCertificateRequest tries to accept a certificate request according to the quotas.
// Return true if accepted and the requests per days quota value
func (s *state) TryAcceptCertificateRequest(issuer utils.IssuerKey) (bool, int) {
	return s.quotas.TryAccept(issuer)
}

func (s *state) IssuerNamesForSecret(secretKey utils.IssuerSecretKey) utils.IssuerKeySet {
	return s.secrets.IssuerNamesFor(secretKey)
}

func (s *state) RememberIssuerSecret(issuer utils.IssuerKey, secretRef *v1.SecretReference, hash string) {
	s.secrets.RememberIssuerSecret(issuer, secretRef, hash)
}

func (s *state) GetIssuerSecretHash(issuerKey utils.IssuerKey) string {
	return s.secrets.GetIssuerSecretHash(issuerKey)
}

// RememberAltIssuerSecret for migration
// This method is only needed for a bugfix for migrating v0.7.x to v0.8.x an can be deleted after v0.9.0
func (s *state) RememberAltIssuerSecret(issuer utils.IssuerKey, secretRef *v1.SecretReference, hash string) {
	s.altSecrets.RememberIssuerSecret(issuer, secretRef, hash)
}

// GetAltIssuerSecretHash for migration
// This method is only needed for a bugfix for migrating v0.7.x to v0.8.x an can be deleted after v0.9.0
func (s *state) GetAltIssuerSecretHash(issuerKey utils.IssuerKey) string {
	return s.altSecrets.GetIssuerSecretHash(issuerKey)
}

func (s *state) IssuerNamesForEABSecret(secretKey utils.IssuerSecretKey) utils.IssuerKeySet {
	return s.eabSecrets.IssuerNamesFor(secretKey)
}

func (s *state) RememberIssuerEABSecret(issuer utils.IssuerKey, secretRef *v1.SecretReference, hash string) {
	s.eabSecrets.RememberIssuerSecret(issuer, secretRef, hash)
}

func (s *state) AddRenewalOverdue(certName resources.ObjectName) bool {
	return s.overdueCerts.Add(certName)
}

func (s *state) RemoveRenewalOverdue(certName resources.ObjectName) bool {
	return s.overdueCerts.Remove(certName)
}

func (s *state) GetAllRenewalOverdue() []resources.ObjectName {
	return s.overdueCerts.AsArray()
}

func (s *state) GetRenewalOverdueCount() int {
	return s.overdueCerts.Size()
}

func (s *state) AddRevoked(certName resources.ObjectName) bool {
	return s.revokedCerts.Add(certName)
}

func (s *state) RemoveRevoked(certName resources.ObjectName) bool {
	return s.revokedCerts.Remove(certName)
}

func (s *state) GetAllRevoked() []resources.ObjectName {
	return s.revokedCerts.AsArray()
}

func (s *state) GetRevokedCount() int {
	return s.revokedCerts.Size()
}

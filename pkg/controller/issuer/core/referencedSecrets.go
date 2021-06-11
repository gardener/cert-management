/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package core

import (
	"sync"

	"github.com/gardener/cert-management/pkg/cert/utils"
	v1 "k8s.io/api/core/v1"
)

// NewReferencedSecrets create a ReferencedSecrets
func NewReferencedSecrets() *ReferencedSecrets {
	return &ReferencedSecrets{
		secretToIssuers: map[utils.IssuerSecretKey]utils.IssuerKeySet{},
		issuerToSecret:  map[utils.IssuerKey]secretAndHash{},
	}
}

type secretAndHash struct {
	secretName utils.IssuerSecretKey
	hash       string
}

// ReferencedSecrets stores references between issuers and their secrets.
type ReferencedSecrets struct {
	lock            sync.Mutex
	secretToIssuers map[utils.IssuerSecretKey]utils.IssuerKeySet
	issuerToSecret  map[utils.IssuerKey]secretAndHash
}

// RememberIssuerSecret stores a secretRef for an issuer.
func (rs *ReferencedSecrets) RememberIssuerSecret(issuerKey utils.IssuerKey, secretRef *v1.SecretReference, hash string) bool {
	rs.lock.Lock()
	defer rs.lock.Unlock()

	if secretRef == nil {
		return rs.removeIssuer(issuerKey)
	}
	secretKey := utils.NewIssuerSecretKey(issuerKey.Cluster(), secretRef.Namespace, secretRef.Name)
	return rs.updateIssuerSecret(issuerKey, secretKey, hash)
}

// RemoveIssuer removes all secretRefs for an issuer.
func (rs *ReferencedSecrets) RemoveIssuer(issuerKey utils.IssuerKey) bool {
	rs.lock.Lock()
	defer rs.lock.Unlock()

	return rs.removeIssuer(issuerKey)
}

// GetIssuerSecretHash gets the for an issuer secret
func (rs *ReferencedSecrets) GetIssuerSecretHash(issuerKey utils.IssuerKey) string {
	rs.lock.Lock()
	defer rs.lock.Unlock()

	obj, ok := rs.issuerToSecret[issuerKey]
	if !ok {
		return ""
	}
	return obj.hash
}

// IssuerNamesFor finds issuers for given secret name.
func (rs *ReferencedSecrets) IssuerNamesFor(secretKey utils.IssuerSecretKey) utils.IssuerKeySet {
	rs.lock.Lock()
	defer rs.lock.Unlock()

	set, ok := rs.secretToIssuers[secretKey]
	if !ok {
		return nil
	}
	return set.Copy()
}

func (rs *ReferencedSecrets) removeIssuer(issuerKey utils.IssuerKey) bool {
	obj, ok := rs.issuerToSecret[issuerKey]
	if ok {
		delete(rs.issuerToSecret, issuerKey)
		rs.secretToIssuers[obj.secretName].Remove(issuerKey)
		if len(rs.secretToIssuers[obj.secretName]) == 0 {
			delete(rs.secretToIssuers, obj.secretName)
		}
	}
	return ok
}

func (rs *ReferencedSecrets) updateIssuerSecret(issuerKey utils.IssuerKey, secretKey utils.IssuerSecretKey, hash string) bool {
	old, ok := rs.issuerToSecret[issuerKey]
	if ok && old.secretName == secretKey && old.hash == hash {
		return false
	}

	rs.removeIssuer(issuerKey)

	rs.issuerToSecret[issuerKey] = secretAndHash{secretKey, hash}
	set := rs.secretToIssuers[secretKey]
	if set == nil {
		set = utils.IssuerKeySet{}
		rs.secretToIssuers[secretKey] = set
	}
	set.Add(issuerKey)

	return true
}

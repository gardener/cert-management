/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package core

import (
	"sync"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NewReferencedSecrets create a ReferencedSecrets
func NewReferencedSecrets() *ReferencedSecrets {
	return &ReferencedSecrets{
		secretToIssuers: map[SecretKey]sets.Set[IssuerKey]{},
		issuerToSecret:  map[IssuerKey]secretAndHash{},
	}
}

type secretAndHash struct {
	secretName SecretKey
	hash       string
}

// ReferencedSecrets stores references between issuers and their secrets.
type ReferencedSecrets struct {
	lock            sync.Mutex
	secretToIssuers map[SecretKey]sets.Set[IssuerKey]
	issuerToSecret  map[IssuerKey]secretAndHash
}

// RememberIssuerSecret stores a secretRef for an issuer.
func (rs *ReferencedSecrets) RememberIssuerSecret(issuerKey IssuerKey, secretRef *v1.SecretReference, hash string) bool {
	rs.lock.Lock()
	defer rs.lock.Unlock()

	if secretRef == nil {
		return rs.removeIssuer(issuerKey)
	}
	secretKey := NewSecretKey(client.ObjectKey{Namespace: secretRef.Namespace, Name: secretRef.Name}, issuerKey.IsFromSecondaryCluster())
	return rs.updateIssuerSecret(issuerKey, secretKey, hash)
}

// RemoveIssuer removes all secretRefs for an issuer.
func (rs *ReferencedSecrets) RemoveIssuer(issuerKey IssuerKey) bool {
	rs.lock.Lock()
	defer rs.lock.Unlock()

	return rs.removeIssuer(issuerKey)
}

// GetIssuerSecretHash gets the for an issuer secret
func (rs *ReferencedSecrets) GetIssuerSecretHash(issuerKey IssuerKey) string {
	rs.lock.Lock()
	defer rs.lock.Unlock()

	obj, ok := rs.issuerToSecret[issuerKey]
	if !ok {
		return ""
	}
	return obj.hash
}

// IssuerNamesFor finds issuers for given secret name.
func (rs *ReferencedSecrets) IssuerNamesFor(secretKey SecretKey) sets.Set[IssuerKey] {
	rs.lock.Lock()
	defer rs.lock.Unlock()

	set, ok := rs.secretToIssuers[secretKey]
	if !ok {
		return nil
	}
	return sets.New(set.UnsortedList()...)
}

func (rs *ReferencedSecrets) removeIssuer(issuerKey IssuerKey) bool {
	obj, ok := rs.issuerToSecret[issuerKey]
	if ok {
		delete(rs.issuerToSecret, issuerKey)
		rs.secretToIssuers[obj.secretName].Delete(issuerKey)
		if len(rs.secretToIssuers[obj.secretName]) == 0 {
			delete(rs.secretToIssuers, obj.secretName)
		}
	}
	return ok
}

func (rs *ReferencedSecrets) updateIssuerSecret(issuerKey IssuerKey, secretKey SecretKey, hash string) bool {
	old, ok := rs.issuerToSecret[issuerKey]
	if ok && old.secretName == secretKey && old.hash == hash {
		return false
	}

	rs.removeIssuer(issuerKey)

	rs.issuerToSecret[issuerKey] = secretAndHash{secretKey, hash}
	set := rs.secretToIssuers[secretKey]
	if set == nil {
		set = sets.Set[IssuerKey]{}
		rs.secretToIssuers[secretKey] = set
	}
	set.Insert(issuerKey)

	return true
}

/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package core

import (
	v1 "k8s.io/api/core/v1"
	"sync"

	"github.com/gardener/controller-manager-library/pkg/resources"
)

// NewReferencedSecrets create a ReferencedSecrets
func NewReferencedSecrets() *ReferencedSecrets {
	return &ReferencedSecrets{
		secretToIssuers: map[resources.ObjectName]resources.ObjectNameSet{},
		issuerToSecret:  map[resources.ObjectName]secretAndHash{},
	}
}

type secretAndHash struct {
	secretName resources.ObjectName
	hash       string
}

// ReferencedSecrets stores references between issuers and their secrets.
type ReferencedSecrets struct {
	lock            sync.Mutex
	secretToIssuers map[resources.ObjectName]resources.ObjectNameSet
	issuerToSecret  map[resources.ObjectName]secretAndHash
}

// RememberIssuerSecret stores a secretRef for an issuer.
func (rs *ReferencedSecrets) RememberIssuerSecret(issuerName resources.ObjectName, secretRef *v1.SecretReference, hash string) bool {
	rs.lock.Lock()
	defer rs.lock.Unlock()

	if secretRef == nil {
		return rs.removeIssuer(issuerName)
	}
	secretName := newObjectName(secretRef.Namespace, secretRef.Name)
	return rs.updateIssuerSecret(issuerName, secretName, hash)
}

// RemoveIssuer removes all secretRefs for an issuer.
func (rs *ReferencedSecrets) RemoveIssuer(issuerName resources.ObjectName) bool {
	rs.lock.Lock()
	defer rs.lock.Unlock()

	return rs.removeIssuer(issuerName)
}

// GetIssuerSecretHash gets the for an issuer secret
func (rs *ReferencedSecrets) GetIssuerSecretHash(issuerName resources.ObjectName) string {
	rs.lock.Lock()
	defer rs.lock.Unlock()

	obj, ok := rs.issuerToSecret[issuerName]
	if !ok {
		return ""
	}
	return obj.hash
}

// IssuerNamesFor finds issuers for given secret name.
func (rs *ReferencedSecrets) IssuerNamesFor(secretName resources.ObjectName) resources.ObjectNameSet {
	rs.lock.Lock()
	defer rs.lock.Unlock()

	set, ok := rs.secretToIssuers[secretName]
	if !ok {
		return nil
	}
	return set.Copy()
}

func (rs *ReferencedSecrets) removeIssuer(issuerName resources.ObjectName) bool {
	obj, ok := rs.issuerToSecret[issuerName]
	if ok {
		delete(rs.issuerToSecret, issuerName)
		rs.secretToIssuers[obj.secretName].Remove(issuerName)
		if len(rs.secretToIssuers[obj.secretName]) == 0 {
			delete(rs.secretToIssuers, obj.secretName)
		}
	}
	return ok
}

func (rs *ReferencedSecrets) updateIssuerSecret(issuerName, secretName resources.ObjectName, hash string) bool {
	old, ok := rs.issuerToSecret[issuerName]
	if ok && old.secretName == secretName && old.hash == hash {
		return false
	}

	rs.removeIssuer(issuerName)

	rs.issuerToSecret[issuerName] = secretAndHash{secretName, hash}
	set := rs.secretToIssuers[secretName]
	if set == nil {
		set = resources.ObjectNameSet{}
		rs.secretToIssuers[secretName] = set
	}
	set.Add(issuerName)

	return true
}

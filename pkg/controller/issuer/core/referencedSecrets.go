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
	v1 "k8s.io/api/core/v1"
	"sync"

	"github.com/gardener/controller-manager-library/pkg/resources"
)

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

type ReferencedSecrets struct {
	lock            sync.Mutex
	secretToIssuers map[resources.ObjectName]resources.ObjectNameSet
	issuerToSecret  map[resources.ObjectName]secretAndHash
}

func (rs *ReferencedSecrets) RememberIssuerSecret(issuerName resources.ObjectName, secretRef *v1.SecretReference, hash string) bool {
	rs.lock.Lock()
	defer rs.lock.Unlock()

	if secretRef == nil {
		return rs.removeIssuer(issuerName)
	}
	secretName := newObjectName(secretRef.Namespace, secretRef.Name)
	return rs.updateIssuerSecret(issuerName, secretName, hash)
}

func (rs *ReferencedSecrets) RemoveIssuer(issuerName resources.ObjectName) bool {
	rs.lock.Lock()
	defer rs.lock.Unlock()

	return rs.removeIssuer(issuerName)
}

func (rs *ReferencedSecrets) GetIssuerSecretHash(issuerName resources.ObjectName) string {
	rs.lock.Lock()
	defer rs.lock.Unlock()

	obj, ok := rs.issuerToSecret[issuerName]
	if !ok {
		return ""
	}
	return obj.hash
}

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

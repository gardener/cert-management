/*
 * SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package utils

import (
	"fmt"

	"github.com/gardener/controller-manager-library/pkg/resources"

	"github.com/gardener/cert-management/pkg/shared"
)

// Cluster is the cluster type
type Cluster = shared.Cluster

const (
	// ClusterDefault is the default cluster
	ClusterDefault = shared.ClusterDefault
	// ClusterTarget is the target cluster
	ClusterTarget = shared.ClusterTarget
)

// IssuerKey provides cluster, name and namespace of an issuer
type IssuerKey struct {
	cluster   Cluster
	namespace string
	name      string
}

// NewIssuerKey creates key for an issuer.
// namespace is ignored for default cluster
func NewIssuerKey(cluster Cluster, namespace, name string) IssuerKey {
	if cluster == ClusterDefault {
		namespace = ""
	}
	return IssuerKey{cluster: cluster, namespace: namespace, name: name}
}

// NewDefaultClusterIssuerKey creates key for an issuer on the default cluster
func NewDefaultClusterIssuerKey(name string) IssuerKey {
	return IssuerKey{cluster: ClusterDefault, name: name}
}

// Name returns the issuer name
func (k IssuerKey) Name() string {
	return k.name
}

// Namespace returns the issuer namespace (namespace is empty if it is on default cluster)
func (k IssuerKey) Namespace() string {
	return k.namespace
}

// NamespaceOrDefault returns the issuer namespace or the given default if it is on default cluster
func (k IssuerKey) NamespaceOrDefault(def string) string {
	if k.cluster == ClusterDefault {
		return def
	}
	return k.namespace
}

// Cluster returns the issuer cluster
func (k IssuerKey) Cluster() Cluster {
	return k.cluster
}

// Secondary returns true if it is a provided issuer from the default cluster ("secondary" cluster in the new wording).
func (k IssuerKey) Secondary() bool {
	return k.cluster == ClusterDefault
}

// ClusterName returns the cluster name
func (k IssuerKey) ClusterName() string {
	switch k.cluster {
	case ClusterDefault:
		return "default"
	case ClusterTarget:
		return "target"
	}
	return ""
}

// String returns the string representation
func (k IssuerKey) String() string {
	if k.cluster == ClusterDefault {
		return k.name
	}
	return fmt.Sprintf("target:%s/%s", k.namespace, k.name)
}

// ObjectName returns the object name for the issuer key.
// If it is on the default cluster, the given namespace is used.
func (k IssuerKey) ObjectName(def string) resources.ObjectName {
	return resources.NewObjectName(k.NamespaceOrDefault(def), k.name)
}

/////////////////////////////////////////////////////////////////////

// IssuerKeySet is a set of IssuerKeys
type IssuerKeySet map[IssuerKey]struct{}

// NewIssuerKeySet creates a new set
func NewIssuerKeySet(keys ...IssuerKey) IssuerKeySet {
	set := IssuerKeySet{}
	if len(keys) > 0 {
		set.Add(keys...)
	}
	return set
}

// Add adds keys to the set
func (s IssuerKeySet) Add(keys ...IssuerKey) {
	for _, key := range keys {
		s[key] = struct{}{}
	}
}

// Remove removes a key from the set
func (s IssuerKeySet) Remove(key IssuerKey) {
	delete(s, key)
}

// Contains checks if set contains the key
func (s IssuerKeySet) Contains(key IssuerKey) bool {
	_, ok := s[key]
	return ok
}

// Copy creates a copy of the set
func (s IssuerKeySet) Copy() IssuerKeySet {
	set := IssuerKeySet{}
	for key := range s {
		set[key] = struct{}{}
	}
	return set
}

/////////////////////////////////////////////////////////////////////

// IssuerSecretKey is the key for an issuer secret
type IssuerSecretKey struct {
	IssuerKey
}

// NewIssuerSecretKey creates key for an issuer secret.
// namespace is ignored for default cluster
func NewIssuerSecretKey(cluster Cluster, namespace, name string) IssuerSecretKey {
	if cluster == ClusterDefault {
		namespace = ""
	}
	return IssuerSecretKey{IssuerKey{cluster: cluster, namespace: namespace, name: name}}
}

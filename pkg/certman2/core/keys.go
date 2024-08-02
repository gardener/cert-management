/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package core

import (
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// IssuerKey provides object key and cluster of an issuer
type IssuerKey struct {
	client.ObjectKey
	secondary bool
}

// NewIssuerKey creates key for an issuer.
func NewIssuerKey(key client.ObjectKey, secondary bool) IssuerKey {
	return IssuerKey{ObjectKey: key, secondary: secondary}
}

// IsFromSecondaryCluster returns true if issuer is from secondary cluster.
func (k IssuerKey) IsFromSecondaryCluster() bool {
	return k.secondary
}

// SecretKey provides object key and cluster of a secret
type SecretKey struct {
	client.ObjectKey
	secondary bool
}

// NewSecretKey creates key for a secret.
func NewSecretKey(key client.ObjectKey, secondary bool) SecretKey {
	return SecretKey{ObjectKey: key, secondary: secondary}
}

// IsFromSecondaryCluster returns true if secret is from secondary cluster.
func (k SecretKey) IsFromSecondaryCluster() bool {
	return k.secondary
}

func ObjectKeyFromSecretReference(secretRef *corev1.SecretReference) client.ObjectKey {
	return client.ObjectKey{Namespace: secretRef.Namespace, Name: secretRef.Name}
}

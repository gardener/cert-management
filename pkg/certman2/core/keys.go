/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package core

import (
	"github.com/gardener/cert-management/pkg/cert/utils"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// IssuerKey provides object key and cluster of an issuer
type IssuerKey struct {
	client.ObjectKey
	secondary bool
}

func (k IssuerKey) Name() string {
	return k.ObjectKey.Name
}

func (k IssuerKey) Namespace() string {
	return k.ObjectKey.Namespace
}

func (k IssuerKey) Cluster() utils.Cluster {
	if k.secondary {
		return utils.ClusterDefault
	}
	return utils.ClusterTarget
}

// Secondary returns true if issuer is from secondary cluster.
func (k IssuerKey) Secondary() bool {
	return k.secondary
}

func (k IssuerKey) String() string {
	if k.secondary {
		return k.ObjectKey.Name
	}
	return "target:" + k.ObjectKey.String()
}

var _ utils.IssuerKeyItf = IssuerKey{}

// NewIssuerKey creates key for an issuer.
func NewIssuerKey(key client.ObjectKey, secondary bool) IssuerKey {
	return IssuerKey{ObjectKey: key, secondary: secondary}
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

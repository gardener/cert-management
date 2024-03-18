/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package kubernetes

import (
	kubernetesutils "github.com/gardener/gardener/pkg/utils/kubernetes"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

// EmptyCABundleCertificateSecret returns a v1 Secret with basic metadata filled only.
func EmptyCABundleCertificateSecret(name, namespace string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
}

// ReconcileCABundleCertificateSecret adjusts the given 'secret' and prepares it to store the 'bundle' inside.
func ReconcileCABundleCertificateSecret(secret *corev1.Secret, bundle []byte) {
	secret.Data = map[string][]byte{
		"bundle.crt": bundle,
	}

	utilruntime.Must(kubernetesutils.MakeUnique(secret))
}

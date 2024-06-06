/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package source

import (
	"strings"

	"github.com/gardener/controller-manager-library/pkg/resources"
)

func requireFinalizer(src resources.Object, cluster resources.Cluster) bool {
	return src.GetCluster() != cluster
}

// ExtractSecretLabels extracts label key value map from annotation.
func ExtractSecretLabels(objData resources.ObjectData) (secretLabels map[string]string) {
	if labels, ok := resources.GetAnnotation(objData, AnnotCertSecretLabels); ok {
		secretLabels = map[string]string{}
		for _, pair := range strings.Split(labels, ",") {
			pair = strings.TrimSpace(pair)
			items := strings.SplitN(pair, "=", 2)
			if len(items) == 2 {
				secretLabels[items[0]] = items[1]
			}
		}
	}
	return
}

// CopyDNSRecordsAnnotations extracts DNSRecord related annotations.
func CopyDNSRecordsAnnotations(data resources.ObjectData) (annotations map[string]string) {
	for _, annotKey := range []string{AnnotDNSRecordProviderType, AnnotDNSRecordSecretRef} {
		if value := data.GetAnnotations()[annotKey]; value != "" {
			if annotations == nil {
				annotations = map[string]string{}
			}
			annotations[annotKey] = value
		}
	}
	return
}

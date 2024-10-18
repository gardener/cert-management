/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package source

import (
	"context"
	"fmt"

	"github.com/gardener/cert-management/pkg/cert/source"
	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// TLSDataCollector collects TLS secret names for hosts.
type TLSDataCollector func(ctx context.Context, obj client.Object) ([]*TLSData, error)

// TLSData contains the collection results: secret name and host list.
type TLSData struct {
	SecretNamespace string
	SecretName      string
	Hosts           []string
}

// GetCertInputByCollector collects data from annotations and from the resources needed for creating certificates.
func GetCertInputByCollector(ctx context.Context, log logr.Logger, obj client.Object, tlsDataCollector TLSDataCollector) (CertInputMap, error) {
	inputMap := CertInputMap{}

	if obj.GetAnnotations()[AnnotationPurposeKey] != AnnotationPurposeValueManaged {
		return nil, nil
	}

	tlsDataArray, err := tlsDataCollector(ctx, obj)
	if err != nil {
		return inputMap, err
	}
	if tlsDataArray == nil {
		log.V(5).Info("No TLS data")
		return inputMap, nil
	}

	annotatedDomains, cn := getDomainsFromAnnotations(obj.GetAnnotations(), false)
	for _, tls := range tlsDataArray {
		if tls.SecretName == "" {
			err = fmt.Errorf("tls entry for hosts %s has no secretName", source.DomainsString(tls.Hosts))
			continue
		}
		var domains []string
		if annotatedDomains != nil {
			domains = annotatedDomains
		} else {
			domains = mergeCommonName(cn, tls.Hosts)
		}
		key := client.ObjectKey{Namespace: tls.SecretNamespace, Name: tls.SecretName}
		inputMap[key] = augmentFromCommonAnnotations(obj.GetAnnotations(), CertInput{
			SecretObjectKey: key,
			Domains:         domains,
		})
	}
	return inputMap, err
}

func mergeCommonName(cn string, hosts []string) []string {
	if cn == "" {
		return hosts
	}
	result := []string{cn}
	for _, host := range hosts {
		if host != cn {
			result = append(result, host)
		}
	}
	return result
}

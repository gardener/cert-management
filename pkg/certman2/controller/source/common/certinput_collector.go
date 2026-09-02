/*
 * SPDX-FileCopyrightText: Contributors to the Gardener project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package common

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/cert-management/pkg/certman2/core"
)

// TLSDataCollector collects TLS secret names for hosts.
type TLSDataCollector func(ctx context.Context, obj client.Object) ([]*TLSData, error)

// TLSData contains the collection results: secret name and host list.
type TLSData struct {
	SecretNamespace string
	SecretName      string
	Hosts           []string
	SectionName     string
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
			err = fmt.Errorf("tls entry for hosts %s has no secretName", core.DomainsString(tls.Hosts))
			continue
		}
		var domains []string
		if annotatedDomains != nil {
			domains = annotatedDomains
		} else {
			domains = mergeCommonName(cn, tls.Hosts)
		}
		key := client.ObjectKey{Namespace: tls.SecretNamespace, Name: tls.SecretName}
		if existing, ok := inputMap[key]; ok {
			// Multiple listeners may reference the same certificate secret (e.g. distinct
			// listener section names sharing one certificateRef). Merge their domains instead
			// of overwriting, so no host is silently dropped.
			existing.Domains = mergeDomains(existing.Domains, domains)
			inputMap[key] = existing
			continue
		}
		inputMap[key] = augmentFromCommonAnnotations(obj.GetAnnotations(), CertInput{
			SecretObjectKey: key,
			Domains:         domains,
		})
	}
	return inputMap, err
}

// mergeDomains appends domains from add that are not already present in base, preserving order.
func mergeDomains(base, add []string) []string {
	seen := make(map[string]struct{}, len(base))
	for _, d := range base {
		seen[d] = struct{}{}
	}
	for _, d := range add {
		if _, ok := seen[d]; !ok {
			seen[d] = struct{}{}
			base = append(base, d)
		}
	}
	return base
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

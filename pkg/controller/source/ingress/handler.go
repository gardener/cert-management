/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package ingress

import (
	"fmt"
	"strings"

	api "k8s.io/api/extensions/v1beta1"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"

	"github.com/gardener/cert-management/pkg/cert/source"
)

// CIngressSource is the ingress CertSource
type CIngressSource struct {
	source.DefaultCertSource
}

const (
	// AnnotationPurposeKey is the annotation key for the purpose
	AnnotationPurposeKey = "cert.gardener.cloud/purpose"
	// AnnotationPurposeValueManaged is the managed value for the purpose annotation
	AnnotationPurposeValueManaged = "managed"
	// DeprecatedLabelNamePurpose is the label key for the purpose
	DeprecatedLabelNamePurpose = "garden.sapcloud.io/purpose"
	// DeprecatedLabelValueManaged is the managed value for the purpose label
	DeprecatedLabelValueManaged = "managed-cert"
)

// NewIngressSource creates a CertSource
func NewIngressSource(_ controller.Interface) (source.CertSource, error) {
	return &CIngressSource{DefaultCertSource: source.DefaultCertSource{Events: map[resources.ClusterObjectKey]map[string]string{}}}, nil
}

// GetCertsInfo returns CertsInfo for the given object
func (s *CIngressSource) GetCertsInfo(logger logger.LogContext, obj resources.Object, current *source.CertCurrentState) (*source.CertsInfo, error) {
	info := s.NewCertsInfo(logger, obj)

	data := obj.Data().(*api.Ingress)
	annotValue, _ := resources.GetAnnotation(data, AnnotationPurposeKey)
	labelValue, _ := resources.GetLabel(data, DeprecatedLabelNamePurpose)
	managed := annotValue == AnnotationPurposeValueManaged || labelValue == DeprecatedLabelValueManaged
	if !managed || data.Spec.TLS == nil {
		return info, nil
	}

	cn, _ := resources.GetAnnotation(data, source.AnnotCommonName)
	cn = strings.TrimSpace(cn)
	var issuer *string
	annotatedIssuer, ok := resources.GetAnnotation(data, source.AnnotIssuer)
	if ok {
		issuer = &annotatedIssuer
	}
	var err error
	for _, tls := range data.Spec.TLS {
		if tls.SecretName == "" {
			err = fmt.Errorf("tls entry for hosts %s has no secretName", source.DomainsString(tls.Hosts))
			continue
		}
		var domains []string
		dnsnames, ok := resources.GetAnnotation(data, source.AnnotCertDNSNames)
		if ok {
			if cn != "" {
				domains = []string{cn}
			}
			for _, e := range strings.Split(dnsnames, ",") {
				e = strings.TrimSpace(e)
				if e != "" && e != cn {
					domains = append(domains, e)
				}
			}
		} else {
			domains = mergeCommonName(cn, tls.Hosts)
		}
		info.Certs[tls.SecretName] = source.CertInfo{SecretName: tls.SecretName, Domains: domains, IssuerName: issuer}
	}
	return info, err
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

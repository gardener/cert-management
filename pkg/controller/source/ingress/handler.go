/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package ingress

import (
	"fmt"
	"strconv"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	networkingv1beta1 "k8s.io/api/networking/v1beta1"

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
func (s *CIngressSource) GetCertsInfo(logger logger.LogContext, obj resources.Object, _ *source.CertCurrentState) (*source.CertsInfo, error) {
	info := s.NewCertsInfo(logger, obj)

	annotValue, _ := resources.GetAnnotation(obj.Data(), AnnotationPurposeKey)
	labelValue, _ := resources.GetLabel(obj.Data(), DeprecatedLabelNamePurpose)
	managed := annotValue == AnnotationPurposeValueManaged || labelValue == DeprecatedLabelValueManaged
	if !managed {
		logger.Debug("No annotation " + AnnotationPurposeKey + "=" + AnnotationPurposeValueManaged)
		return info, nil
	}
	tlsDataArray, err := extractTLSData(obj)
	if err != nil {
		return info, err
	}
	if tlsDataArray == nil {
		logger.Debug("No TLS data")
		return info, nil
	}

	followCNAME := false
	if value, ok := resources.GetAnnotation(obj.Data(), source.AnnotFollowCNAME); ok {
		followCNAME, _ = strconv.ParseBool(value)
	}

	preferredChain, _ := resources.GetAnnotation(obj.Data(), source.AnnotPreferredChain)

	cn, _ := resources.GetAnnotation(obj.Data(), source.AnnotCommonName)
	cn = strings.TrimSpace(cn)
	var issuer *string
	annotatedIssuer, ok := resources.GetAnnotation(obj.Data(), source.AnnotIssuer)
	if ok {
		issuer = &annotatedIssuer
	}
	for _, tls := range tlsDataArray {
		if tls.SecretName == "" {
			err = fmt.Errorf("tls entry for hosts %s has no secretName", source.DomainsString(tls.Hosts))
			continue
		}
		var domains []string
		dnsnames, ok := resources.GetAnnotation(obj.Data(), source.AnnotCertDNSNames)
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
		info.Certs[tls.SecretName] = source.CertInfo{
			SecretName:     tls.SecretName,
			Domains:        domains,
			IssuerName:     issuer,
			FollowCNAME:    followCNAME,
			SecretLabels:   source.ExtractSecretLabels(obj),
			PreferredChain: preferredChain,
		}
	}
	return info, err
}

type tlsData struct {
	SecretName string
	Hosts      []string
}

func extractTLSData(obj resources.Object) ([]*tlsData, error) {
	array := []*tlsData{}
	switch data := obj.Data().(type) {
	case *networkingv1beta1.Ingress:
		if data.Spec.TLS == nil {
			return nil, nil
		}
		for _, item := range data.Spec.TLS {
			array = append(array, &tlsData{
				SecretName: item.SecretName,
				Hosts:      item.Hosts,
			})
		}
		return array, nil
	case *networkingv1.Ingress:
		if data.Spec.TLS == nil {
			return nil, nil
		}
		for _, item := range data.Spec.TLS {
			array = append(array, &tlsData{
				SecretName: item.SecretName,
				Hosts:      item.Hosts,
			})
		}
		return array, nil
	default:
		return nil, fmt.Errorf("unexpected ingress type: %#v", obj.Data())
	}
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

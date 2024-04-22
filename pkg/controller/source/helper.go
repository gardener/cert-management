/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package source

import (
	"fmt"
	"strconv"

	"github.com/gardener/cert-management/pkg/cert/source"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
)

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

// TLSDataCollector collects TLS secret names for hosts.
type TLSDataCollector func(objData resources.ObjectData) ([]*TLSData, error)

type TLSData struct {
	SecretNamespace *string
	SecretName      string
	Hosts           []string
}

func GetCertsInfoByCollector(logger logger.LogContext, objData resources.ObjectData, tlsDataCollector TLSDataCollector) (*source.CertsInfo, error) {
	info := source.NewCertsInfo()

	annotValue, _ := resources.GetAnnotation(objData, AnnotationPurposeKey)
	labelValue, _ := resources.GetLabel(objData, DeprecatedLabelNamePurpose)
	managed := annotValue == AnnotationPurposeValueManaged || labelValue == DeprecatedLabelValueManaged
	if !managed {
		logger.Debug("No annotation " + AnnotationPurposeKey + "=" + AnnotationPurposeValueManaged)
		return info, nil
	}
	tlsDataArray, err := tlsDataCollector(objData)
	if err != nil {
		return info, err
	}
	if tlsDataArray == nil {
		logger.Debug("No TLS data")
		return info, nil
	}

	followCNAME := false
	if value, ok := resources.GetAnnotation(objData, source.AnnotFollowCNAME); ok {
		followCNAME, _ = strconv.ParseBool(value)
	}

	preferredChain, _ := resources.GetAnnotation(objData, source.AnnotPreferredChain)
	algorithm, _ := resources.GetAnnotation(objData, source.AnnotPrivateKeyAlgorithm)
	keySize := 0
	if keySizeStr, ok := resources.GetAnnotation(objData, source.AnnotPrivateKeySize); ok {
		if value, err := strconv.Atoi(keySizeStr); err == nil {
			keySize = value
		}
	}

	annotatedDomains, cn := source.GetDomainsFromAnnotations(objData)

	var issuer *string
	annotatedIssuer, ok := resources.GetAnnotation(objData, source.AnnotIssuer)
	if ok {
		issuer = &annotatedIssuer
	}
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
		key := tls.SecretName
		if tls.SecretNamespace != nil {
			key = *tls.SecretNamespace + "/" + tls.SecretName
		}
		info.Certs[key] = source.CertInfo{
			SecretNamespace:     tls.SecretNamespace,
			SecretName:          tls.SecretName,
			Domains:             domains,
			IssuerName:          issuer,
			FollowCNAME:         followCNAME,
			SecretLabels:        source.ExtractSecretLabels(objData),
			PreferredChain:      preferredChain,
			PrivateKeyAlgorithm: algorithm,
			PrivateKeySize:      keySize,
		}
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

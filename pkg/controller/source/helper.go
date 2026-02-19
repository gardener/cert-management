/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package source

import (
	"fmt"
	"strconv"
	"time"

	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/cert/source"
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

// TLSData contains the collection results: secret name and host list.
type TLSData struct {
	SecretNamespace *string
	SecretName      string
	Hosts           []string
}

// GetCertsInfoByCollector collects data from annotations and from the resources needed for creating certificates.
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
	var keySize api.PrivateKeySize
	if keySizeStr, ok := resources.GetAnnotation(objData, source.AnnotPrivateKeySize); ok {
		if value, err := strconv.ParseInt(keySizeStr, 10, 32); err == nil {
			keySize = api.PrivateKeySize(value) // #nosec G115 -- values are validated anyway
		}
	}

	var encoding api.PrivateKeyEncoding
	if encodingStr, ok := resources.GetAnnotation(objData, source.AnnotPrivateKeyEncoding); ok && encodingStr == string(api.PKCS8) {
		encoding = api.PKCS8
	}

	var renewBefore *metav1.Duration
	if renewBeforeStr, ok := resources.GetAnnotation(objData, source.AnnotRenewBefore); ok {
		if duration, err := time.ParseDuration(renewBeforeStr); err == nil {
			// Validate minimum of 5 minutes
			if duration < 5*time.Minute {
				logger.Warnf("Invalid renew-before annotation value %q: must be at least 5 minutes", renewBeforeStr)
			} else {
				renewBefore = &metav1.Duration{Duration: duration}
			}
		} else {
			logger.Warnf("Invalid renew-before annotation value %q: %v", renewBeforeStr, err)
		}
	}

	annotatedDomains, cn := source.GetDomainsFromAnnotations(objData, false)

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
		secretName := types.NamespacedName{Name: tls.SecretName, Namespace: objData.GetNamespace()}
		if tls.SecretNamespace != nil {
			secretName.Namespace = *tls.SecretNamespace
		}
		info.Certs[secretName] = source.CertInfo{
			SecretName:          secretName,
			Domains:             domains,
			IssuerName:          issuer,
			FollowCNAME:         followCNAME,
			SecretLabels:        source.ExtractSecretLabels(objData),
			PreferredChain:      preferredChain,
			PrivateKeyAlgorithm: algorithm,
			PrivateKeySize:      keySize,
			PrivateKeyEncoding:  encoding,
			RenewBefore:         renewBefore,
			Annotations:         source.CopyDNSRecordsAnnotations(objData),
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

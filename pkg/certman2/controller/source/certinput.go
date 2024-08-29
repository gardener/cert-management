/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package source

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	certmanv1alpha1 "github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
)

// CertInput contains basic certificate data.
type CertInput struct {
	SecretNamespace     string
	SecretName          string
	Domains             []string
	IssuerName          *string
	FollowCNAME         bool
	SecretLabels        map[string]string
	PreferredChain      string
	PrivateKeyAlgorithm string
	PrivateKeySize      int
	Annotations         map[string]string
}

// CertInputMap contains a map of secretName to CertInput.
type CertInputMap map[string]CertInput

func GetCertSourceSpecForService(log logr.Logger, service *corev1.Service) (CertInputMap, error) {
	secretName, ok := service.Annotations[AnnotSecretname]
	if !ok {
		log.V(5).Info("No secret name annotation", "key", AnnotSecretname)
		return nil, nil
	}
	if secretName == "" {
		return nil, fmt.Errorf("empty secret name annotation %q", AnnotSecretname)
	}

	annotatedDomains, _ := GetDomainsFromAnnotations(service, true)
	if annotatedDomains == nil {
		return nil, fmt.Errorf("no valid domain name annotations found for service %q", service.Name)
	}

	var issuer *string
	annotatedIssuer, ok := service.Annotations[AnnotIssuer]
	if ok {
		issuer = &annotatedIssuer
	}

	followCNAME := false
	if value, ok := service.Annotations[AnnotFollowCNAME]; ok {
		followCNAME, _ = strconv.ParseBool(value)
	}
	preferredChain, _ := service.Annotations[AnnotPreferredChain]

	algorithm, _ := service.Annotations[AnnotPrivateKeyAlgorithm]
	keySize := 0
	if keySizeStr, ok := service.Annotations[AnnotPrivateKeySize]; ok {
		if value, err := strconv.Atoi(keySizeStr); err == nil {
			keySize = value
		}
	}

	return CertInputMap{secretName: CertInput{
		SecretNamespace:     service.Namespace,
		SecretName:          secretName,
		Domains:             annotatedDomains,
		IssuerName:          issuer,
		FollowCNAME:         followCNAME,
		SecretLabels:        ExtractSecretLabels(service),
		PreferredChain:      preferredChain,
		PrivateKeyAlgorithm: algorithm,
		PrivateKeySize:      keySize,
		Annotations:         CopyAnnotations(service, AnnotClass, AnnotDNSRecordProviderType, AnnotDNSRecordSecretRef),
	}}, nil
}

// GetDomainsFromAnnotations gets includes annotated DNS names (DNS names from annotation "cert.gardener.cloud/dnsnames"
// or alternatively "dns.gardener.cloud/dnsnames") and the optional common name.
// The common name is added to the returned domain list
func GetDomainsFromAnnotations(obj client.Object, forService bool) (annotatedDomains []string, cn string) {
	a, ok := obj.GetAnnotations()[AnnotCertDNSNames]
	if !ok {
		if forService {
			a, ok = obj.GetAnnotations()[AnnotDnsnames]
			if a == "*" || a == "all" {
				a = ""
				ok = false
			}
		}
		if !ok {
			cn, ok = obj.GetAnnotations()[AnnotCommonName]
			if !ok {
				return nil, ""
			}
			if !forService {
				return nil, cn
			}
		}
	}

	cn, _ = obj.GetAnnotations()[AnnotCommonName]
	cn = strings.TrimSpace(cn)
	annotatedDomains = []string{}
	if cn != "" {
		annotatedDomains = append(annotatedDomains, cn)
	}
	for _, e := range strings.Split(a, ",") {
		e = strings.TrimSpace(e)
		if e != "" && e != cn {
			annotatedDomains = append(annotatedDomains, e)
		}
	}
	return annotatedDomains, cn
}

// ExtractSecretLabels extracts label key value map from annotation.
func ExtractSecretLabels(obj client.Object) (secretLabels map[string]string) {
	if labels, ok := obj.GetAnnotations()[AnnotCertSecretLabels]; ok {
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

// CopyAnnotations extracts DNSRecord related annotations.
func CopyAnnotations(obj client.Object, keys ...string) (annotations map[string]string) {
	for _, annotKey := range keys {
		if value := obj.GetAnnotations()[annotKey]; value != "" {
			if annotations == nil {
				annotations = map[string]string{}
			}
			annotations[annotKey] = value
		}
	}
	return
}

func CreateSpec(src CertInput) certmanv1alpha1.CertificateSpec {
	spec := certmanv1alpha1.CertificateSpec{}
	if len(src.Domains) > 0 {
		if len(src.Domains[0]) <= 64 {
			spec.CommonName = &src.Domains[0]
			spec.DNSNames = normalizeArray(src.Domains[1:])
		} else {
			spec.CommonName = nil
			spec.DNSNames = src.Domains
		}
	}
	if src.IssuerName != nil {
		parts := strings.SplitN(*src.IssuerName, "/", 2)
		if len(parts) == 2 {
			spec.IssuerRef = &certmanv1alpha1.IssuerRef{Namespace: parts[0], Name: parts[1]}
		} else {
			spec.IssuerRef = &certmanv1alpha1.IssuerRef{Name: *src.IssuerName}
		}
	}
	spec.SecretRef = &corev1.SecretReference{
		Name:      src.SecretName,
		Namespace: src.SecretNamespace,
	}
	if src.FollowCNAME {
		spec.FollowCNAME = &src.FollowCNAME
	}
	spec.SecretLabels = src.SecretLabels
	if src.PreferredChain != "" {
		spec.PreferredChain = &src.PreferredChain
	}

	spec.PrivateKey = createPrivateKey(src.PrivateKeyAlgorithm, src.PrivateKeySize)

	return spec
}

func createPrivateKey(algorithm string, size int) *certmanv1alpha1.CertificatePrivateKey {
	if algorithm == "" && size == 0 {
		return nil
	}
	obj := &certmanv1alpha1.CertificatePrivateKey{}
	if algorithm != "" {
		obj.Algorithm = ptr.To(certmanv1alpha1.PrivateKeyAlgorithm(algorithm))
	}
	if size != 0 {
		obj.Size = ptr.To(certmanv1alpha1.PrivateKeySize(size))
	}
	return obj
}

func normalizeArray(a []string) []string {
	if len(a) == 0 {
		return nil
	}
	return a
}

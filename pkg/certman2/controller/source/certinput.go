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

	certmanv1alpha1 "github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CertInput contains basic certificate data.
type CertInput struct {
	SecretObjectKey     client.ObjectKey
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
type CertInputMap map[client.ObjectKey]CertInput

// GetCertSourceSpecForService gets the certificate source spec for a service of type loadbalancer.
func GetCertSourceSpecForService(log logr.Logger, service *corev1.Service) (CertInputMap, error) {
	secretName, ok := service.Annotations[AnnotSecretname]
	if !ok {
		log.V(5).Info("No secret name annotation", "key", AnnotSecretname)
		return nil, nil
	}
	if secretName == "" {
		return nil, fmt.Errorf("empty secret name annotation %q", AnnotSecretname)
	}
	secretNamespace, ok := service.Annotations[AnnotSecretNamespace]
	if !ok {
		secretNamespace = service.Namespace
	}

	annotatedDomains, _ := getDomainsFromAnnotations(service.Annotations, true)
	if annotatedDomains == nil {
		return nil, fmt.Errorf("no valid domain name annotations found for service %q", service.Name)
	}

	secretObjectKey := client.ObjectKey{Namespace: secretNamespace, Name: secretName}
	certInput := augmentFromCommonAnnotations(service.Annotations, CertInput{
		SecretObjectKey: secretObjectKey,
		Domains:         annotatedDomains,
	})
	return CertInputMap{certInput.SecretObjectKey: certInput}, nil
}

func augmentFromCommonAnnotations(annotations map[string]string, certInput CertInput) CertInput {
	if len(annotations) == 0 {
		return certInput
	}

	var issuer *string
	annotatedIssuer, ok := annotations[AnnotIssuer]
	if ok {
		issuer = &annotatedIssuer
	}

	followCNAME := false
	if value, ok := annotations[AnnotFollowCNAME]; ok {
		followCNAME, _ = strconv.ParseBool(value)
	}
	preferredChain := annotations[AnnotPreferredChain]

	algorithm := annotations[AnnotPrivateKeyAlgorithm]
	keySize := 0
	if keySizeStr, ok := annotations[AnnotPrivateKeySize]; ok {
		if value, err := strconv.Atoi(keySizeStr); err == nil {
			keySize = value
		}
	}

	certInput.FollowCNAME = followCNAME
	certInput.IssuerName = issuer
	certInput.PreferredChain = preferredChain
	certInput.PrivateKeyAlgorithm = algorithm
	certInput.PrivateKeySize = keySize
	certInput.SecretLabels = extractSecretLabels(annotations)
	certInput.Annotations = copyAnnotations(annotations, AnnotClass, AnnotDNSRecordProviderType, AnnotDNSRecordSecretRef)
	return certInput
}

// getDomainsFromAnnotations gets includes annotated DNS names (DNS names from annotation "cert.gardener.cloud/dnsnames"
// or alternatively "dns.gardener.cloud/dnsnames") and the optional common name.
// The common name is added to the returned domain list
func getDomainsFromAnnotations(annotations map[string]string, forService bool) (annotatedDomains []string, cn string) {
	a, ok := annotations[AnnotCertDNSNames]
	if !ok {
		if forService {
			a, ok = annotations[AnnotDnsnames]
			if a == "*" || a == "all" {
				a = ""
				ok = false
			}
		}
		if !ok {
			cn, ok = annotations[AnnotCommonName]
			if !ok {
				return nil, ""
			}
			if !forService {
				return nil, cn
			}
		}
	}

	cn = annotations[AnnotCommonName]
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

func extractSecretLabels(annotations map[string]string) (secretLabels map[string]string) {
	if labels, ok := annotations[AnnotCertSecretLabels]; ok {
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

// copyAnnotations extracts DNSRecord related annotations.
func copyAnnotations(annotations map[string]string, keys ...string) (result map[string]string) {
	for _, annotKey := range keys {
		if value := annotations[annotKey]; value != "" {
			if result == nil {
				result = map[string]string{}
			}
			result[annotKey] = value
		}
	}
	return
}

// CreateSpec creates a CertificateSpec from a CertInput.
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
		Name:      src.SecretObjectKey.Name,
		Namespace: src.SecretObjectKey.Namespace,
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
		obj.Size = ptr.To(certmanv1alpha1.PrivateKeySize(size)) // #nosec G115 -- only validated values in int32 range are used
	}
	return obj
}

func normalizeArray(a []string) []string {
	if len(a) == 0 {
		return nil
	}
	return a
}

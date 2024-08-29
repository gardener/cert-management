/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package source

import (
	configv1alpha1 "github.com/gardener/cert-management/pkg/certman2/apis/config/v1alpha1"
)

const (
	// AnnotDnsnames annotation is shared with dns controller manager
	AnnotDnsnames = "dns.gardener.cloud/dnsnames"
	// AnnotClass is the annotation for the cert class
	AnnotClass = "cert.gardener.cloud/class"
	// AnnotSecretname is the annotation for the secret name
	AnnotSecretname = "cert.gardener.cloud/secretname"
	// AnnotIssuer is the annotation for the issuer name
	AnnotIssuer = "cert.gardener.cloud/issuer"
	// AnnotCommonName is the annotation for explicitly specifying the common name
	AnnotCommonName = "cert.gardener.cloud/commonname"
	// AnnotCertDNSNames is the annotation for explicitly specifying the DNS names (if not specified, values from "dns.gardener.cloud/dnsnames" is used)
	AnnotCertDNSNames = "cert.gardener.cloud/dnsnames"
	// AnnotFollowCNAME is the annotation for allowing delegated domains for DNS01 challenge
	AnnotFollowCNAME = "cert.gardener.cloud/follow-cname"
	// AnnotCertSecretLabels is the annotation for setting labels for the secret resource
	// comma-separated format "key1=value1,key2=value2"
	AnnotCertSecretLabels = "cert.gardener.cloud/secret-labels"
	// AnnotPreferredChain is the annotation for the certificate preferred chain
	AnnotPreferredChain = "cert.gardener.cloud/preferred-chain"
	// AnnotPrivateKeyAlgorithm is the annotation key to set the PrivateKeyAlgorithm for a Certificate.
	// If PrivateKeyAlgorithm is specified and `size` is not provided,
	// key size of 256 will be used for `ECDSA` key algorithm and
	// key size of 2048 will be used for `RSA` key algorithm.
	// If unset an algorithm `RSA` will be used.
	AnnotPrivateKeyAlgorithm = "cert.gardener.cloud/private-key-algorithm"
	// AnnotPrivateKeySize is the annotation key to set the size of the private key for a Certificate.
	// If PrivateKeyAlgorithm is set to `RSA`, valid values are `2048`, `3072`, or `4096`,
	// and will default to `2048` if not specified.
	// If PrivateKeyAlgorithm is set to `ECDSA`, valid values are `256` or `384`,
	// and will default to `256` if not specified.
	// No other values are allowed.
	AnnotPrivateKeySize = "cert.gardener.cloud/private-key-size"
	// AnnotDNSRecordProviderType is the annotation for providing the provider type for DNS records.
	AnnotDNSRecordProviderType = "cert.gardener.cloud/dnsrecord-provider-type"
	// AnnotDNSRecordSecretRef is the annotation for providing the secret ref for DNS records.
	AnnotDNSRecordSecretRef = "cert.gardener.cloud/dnsrecord-secret-ref"

	// DefaultClass is the default cert-class
	DefaultClass = configv1alpha1.DefaultClass
)

// NormalizeClass returns the class name or "" if it is the default class.
func NormalizeClass(class string) string {
	if class == DefaultClass {
		return ""
	}
	return class
}

// EquivalentClass returns true if the annotation class are equivalent, i.e. equal after normalizing.
func EquivalentClass(cls1, cls2 string) bool {
	return NormalizeClass(cls1) == NormalizeClass(cls2)
}

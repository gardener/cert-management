/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package shared

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"k8s.io/apimachinery/pkg/util/sets"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
)

// ExtractCommonNameAnDNSNames extracts values from a CSR (Certificate Signing Request).
func ExtractCommonNameAnDNSNames(csr []byte) (cn *string, san []string, err error) {
	certificateRequest, err := extractCertificateRequest(csr)
	if err != nil {
		err = fmt.Errorf("parsing CSR failed: %w", err)
		return
	}
	cnvalue := certificateRequest.Subject.CommonName
	if cnvalue != "" {
		cn = &cnvalue
	}
	san = certificateRequest.DNSNames[:]
	for _, ip := range certificateRequest.IPAddresses {
		san = append(san, ip.String())
	}
	return
}

// ExtractCommonNameFromLiteralSubject parses an LDAP-style literal subject and
// returns its common name (CN), or nil if the subject has no CN or cannot be
// parsed. It is used to populate the certificate status when only a literal
// subject (and no explicit common name) is requested.
func ExtractCommonNameFromLiteralSubject(literalSubject string) *string {
	rdns, err := pki.UnmarshalSubjectStringToRDNSequence(literalSubject)
	if err != nil {
		return nil
	}
	commonName := pki.ExtractCommonNameFromRDNSequence(rdns)
	if commonName == "" {
		return nil
	}
	return &commonName
}

func extractCertificateRequest(csr []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csr)
	if block == nil {
		return nil, fmt.Errorf("decoding CSR failed")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// ToKeyUsages parses a comma-separated list of key usage strings and returns valid KeyUsage values.
func ToKeyUsages(value string) []api.KeyUsage {
	set := sets.NewString()
	for _, usage := range api.AllKeyUsages {
		set.Insert(string(usage))
	}
	var usages []api.KeyUsage
	for usage := range strings.SplitSeq(value, ",") {
		usage = strings.TrimSpace(usage)
		if set.Has(usage) {
			usages = append(usages, api.KeyUsage(usage))
		}
	}
	return usages
}

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
		if set.Has(string(usage)) {
			usages = append(usages, api.KeyUsage(usage))
		}
	}
	return usages
}

/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package utils

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"unicode/utf8"

	"github.com/gardener/controller-manager-library/pkg/resources"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
)

var certificateType = (*api.Certificate)(nil)

// CertificateObject encapsulates the certificate resource object.
type CertificateObject struct {
	resources.Object
}

// Certificate casts the object to certificate.
func (o *CertificateObject) Certificate() *api.Certificate {
	return o.Data().(*api.Certificate)
}

// Certificate returns the certificate object
func Certificate(o resources.Object) *CertificateObject {
	if o.IsA(certificateType) {
		return &CertificateObject{o}
	}
	return nil
}

// Spec returns the certificate spec
func (o *CertificateObject) Spec() *api.CertificateSpec {
	return &o.Certificate().Spec
}

// Status returns the certificate status
func (o *CertificateObject) Status() *api.CertificateStatus {
	return &o.Certificate().Status
}

// SafeCommonName return the common name or "".
func (o *CertificateObject) SafeCommonName() string {
	cn := o.Spec().CommonName
	if cn == nil {
		cn = o.Status().CommonName
	}
	if cn == nil {
		return ""
	}
	return *cn
}

////////////////////////////////////////

// ExtractDomains collects CommonName and DNSNames directly from spec or from CSR.
// The first item is the common name
func ExtractDomains(spec *api.CertificateSpec) ([]string, error) {
	var err error
	cn := spec.CommonName
	if cn == nil || *cn == "" {
		return nil, fmt.Errorf("missing common name")
	}
	dnsNames := spec.DNSNames
	if spec.CommonName != nil {
		if spec.CSR != nil {
			return nil, fmt.Errorf("cannot specify both commonName and csr")
		}
		if len(spec.DNSNames) >= 100 {
			return nil, fmt.Errorf("invalid number of DNS names: %d (max 99)", len(spec.DNSNames))
		}
		count := utf8.RuneCount([]byte(*spec.CommonName))
		if count > 64 {
			return nil, fmt.Errorf("the Common Name is limited to 64 characters (X.509 ASN.1 specification), but first given domain %s has %d characters", *spec.CommonName, count)
		}
	} else {
		if spec.CSR == nil {
			return nil, fmt.Errorf("either domains or csr must be specified")
		}
		cn, dnsNames, err = ExtractCommonNameAnDNSNames(spec.CSR)
		if err != nil {
			return nil, err
		}
	}

	return append([]string{*cn}, dnsNames...), nil
}

// ExtractCommonNameAnDNSNames extracts values from a CSR (Certificate Signing Request).
func ExtractCommonNameAnDNSNames(csr []byte) (cn *string, san []string, err error) {
	certificateRequest, err := extractCertificateRequest(csr)
	if err != nil {
		err = fmt.Errorf("parsing CSR failed: %w", err)
		return
	}
	cnvalue := certificateRequest.Subject.CommonName
	cn = &cnvalue
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

/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package utils

import (
	"fmt"
	"unicode/utf8"

	"github.com/gardener/cert-management/pkg/shared"
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

// SafeFirstDNSName returns the first DNS name (common name if set) or "".
func (o *CertificateObject) SafeFirstDNSName() string {
	cn := o.Spec().CommonName
	if cn != nil {
		return *cn
	}

	if len(o.Spec().DNSNames) > 0 {
		return o.Spec().DNSNames[0]
	}

	cn = o.Status().CommonName
	if cn != nil {
		return *cn
	}

	if len(o.Status().DNSNames) > 0 {
		return o.Status().DNSNames[0]
	}

	return ""
}

////////////////////////////////////////

// ExtractDomains collects CommonName and DNSNames directly from spec or from CSR.
// The first item is the common name if provided.
func ExtractDomains(spec *api.CertificateSpec) ([]string, error) {
	var err error
	cn := spec.CommonName
	dnsNames := spec.DNSNames
	if spec.CommonName != nil || len(spec.DNSNames) > 0 {
		if spec.CSR != nil {
			return nil, fmt.Errorf("cannot specify both commonName and csr")
		}
		if len(spec.DNSNames) >= 100 {
			return nil, fmt.Errorf("invalid number of DNS names: %d (max 99)", len(spec.DNSNames))
		}
		if spec.CommonName != nil {
			count := utf8.RuneCount([]byte(*spec.CommonName))
			if count > 64 {
				return nil, fmt.Errorf("the Common Name is limited to 64 characters (X.509 ASN.1 specification), but first given domain %s has %d characters", *spec.CommonName, count)
			}
		}
	} else {
		if spec.CSR == nil {
			return nil, fmt.Errorf("either domains or csr must be specified")
		}
		cn, dnsNames, err = shared.ExtractCommonNameAnDNSNames(spec.CSR)
		if err != nil {
			return nil, err
		}
	}

	if cn != nil {
		dnsNames = append([]string{*cn}, dnsNames...)
	}
	return dnsNames, nil
}

/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package utils

import (
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

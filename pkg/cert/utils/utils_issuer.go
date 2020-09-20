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

var issuerType = (*api.Issuer)(nil)

// IssuerObject encapsulates the issuer resource object.
type IssuerObject struct {
	resources.Object
}

// Issuer returns the issuer.
func (o *IssuerObject) Issuer() *api.Issuer {
	return o.Data().(*api.Issuer)
}

// Issuer returns the issuer object.
func Issuer(o resources.Object) *IssuerObject {

	if o.IsA(issuerType) {
		return &IssuerObject{o}
	}
	return nil
}

// Spec returns the issuer resource object spec.
func (o *IssuerObject) Spec() *api.IssuerSpec {
	return &o.Issuer().Spec
}

// Status returns the issuer resource object status.
func (o *IssuerObject) Status() *api.IssuerStatus {
	return &o.Issuer().Status
}

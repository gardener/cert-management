/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package utils

import api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"

const (
	// IssuerTypeACME is the issuer type ACME
	IssuerTypeACME = "acme"
	// IssuerTypeCA is the issuer type CA
	IssuerTypeCA = "ca"
)

// IssuerInfo provides name and type of an issuer
type IssuerInfo struct {
	name       string
	issuertype string
}

// NewACMEIssuerInfo creates info for an ACME issuer
func NewACMEIssuerInfo(name string) IssuerInfo {
	return IssuerInfo{name: name, issuertype: IssuerTypeACME}
}

// NewCAIssuerInfo creates info for an CA issuer
func NewCAIssuerInfo(name string) IssuerInfo {
	return IssuerInfo{name: name, issuertype: IssuerTypeCA}
}

// NewIssuerInfoFromIssuer creates info from an issuer object
func NewIssuerInfoFromIssuer(issuer *api.Issuer) IssuerInfo {
	var issuertype string
	if issuer.Spec.ACME != nil {
		issuertype = IssuerTypeACME
	} else if issuer.Spec.CA != nil {
		issuertype = IssuerTypeCA
	}
	return IssuerInfo{name: issuer.Name, issuertype: issuertype}
}

// Name returns the issuer name
func (i *IssuerInfo) Name() string {
	return i.name
}

// IssuerType returns the issuer type
func (i *IssuerInfo) IssuerType() string {
	return i.issuertype
}

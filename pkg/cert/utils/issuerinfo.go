/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package utils

const (
	// IssuerTypeACME is the issuer type ACME
	IssuerTypeACME = "acme"
	// IssuerTypeCA is the issuer type CA
	IssuerTypeCA = "ca"
)

// IssuerInfo provides name and type of an issuer
type IssuerInfo struct {
	key        IssuerKey
	issuertype string
}

// NewACMEIssuerInfo creates info for an ACME issuer
func NewACMEIssuerInfo(key IssuerKey) IssuerInfo {
	return IssuerInfo{key: key, issuertype: IssuerTypeACME}
}

// NewCAIssuerInfo creates info for an CA issuer
func NewCAIssuerInfo(key IssuerKey) IssuerInfo {
	return IssuerInfo{key: key, issuertype: IssuerTypeCA}
}

// Key returns the issuer key
func (i *IssuerInfo) Key() IssuerKey {
	return i.key
}

// IssuerType returns the issuer type
func (i *IssuerInfo) IssuerType() string {
	return i.issuertype
}

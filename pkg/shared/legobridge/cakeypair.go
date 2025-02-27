/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package legobridge

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// TLSKeyPair contains a certificate and a private key.
type TLSKeyPair struct {
	Cert x509.Certificate
	Key  crypto.PrivateKey
}

// CAKeyPairFromSecretData restores a TLSKeyPair from a secret data map.
func CAKeyPairFromSecretData(data map[string][]byte) (*TLSKeyPair, error) {
	certBytes, ok := data[corev1.TLSCertKey]
	if !ok {
		return nil, fmt.Errorf("`%s` data not found in secret", corev1.TLSCertKey)
	}
	cert, err := DecodeCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	keyBytes, ok := data[corev1.TLSPrivateKeyKey]
	if !ok {
		return nil, fmt.Errorf("`%s` data not found in secret", corev1.TLSPrivateKeyKey)
	}
	key, err := bytesToPrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}

	return &TLSKeyPair{Cert: *cert, Key: key}, nil
}

// RawCertInfo returns some info from the CA Certificate.
func (c *TLSKeyPair) RawCertInfo() ([]byte, error) {
	type subject struct {
		Country, Organization, OrganizationalUnit []string
		Locality, Province                        []string
		StreetAddress, PostalCode                 []string
		SerialNumber, CommonName                  string
	}

	certSubject := c.Cert.Subject
	serialNumber := strings.ToUpper(fmt.Sprintf("%x", c.Cert.SerialNumber))
	raw := struct {
		NotBefore, NotAfter time.Time
		Subject             subject
	}{
		NotBefore: c.Cert.NotBefore,
		NotAfter:  c.Cert.NotAfter,
		Subject: subject{
			SerialNumber:       serialNumber,
			CommonName:         certSubject.CommonName,
			Country:            certSubject.Country,
			Organization:       certSubject.Organization,
			OrganizationalUnit: certSubject.OrganizationalUnit,
			Locality:           certSubject.Locality,
			Province:           certSubject.Province,
			StreetAddress:      certSubject.StreetAddress,
			PostalCode:         certSubject.PostalCode,
		},
	}

	certInfo, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("encoding certificate info failed: %w", err)
	}
	return certInfo, nil
}

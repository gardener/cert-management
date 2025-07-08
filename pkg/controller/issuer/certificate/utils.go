/*
 * SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package certificate

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/gardener/controller-manager-library/pkg/resources"
	corev1 "k8s.io/api/core/v1"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/shared/legobridge"
)

// ExtractRequestedAtFromAnnotation extracts the requestedAt timestamp from the annotation cert.gardener.cloud/requestedAt
func ExtractRequestedAtFromAnnotation(obj resources.ObjectData) *time.Time {
	if value, ok := resources.GetAnnotation(obj, AnnotationRequestedAt); ok {
		t, err := time.Parse(time.RFC3339, value)
		if err == nil {
			return &t
		}
	}
	return nil
}

func setRequestedAtAnnotation(obj resources.ObjectData, requestedAt *time.Time) {
	if requestedAt != nil {
		value := requestedAt.UTC().Format(time.RFC3339)
		resources.SetAnnotation(obj, AnnotationRequestedAt, value)
	}
}

// SerialNumberToString get string representation of certificate serial number
func SerialNumberToString(sn *big.Int, compact bool) string {
	if sn == nil {
		return "nil"
	}
	builder := strings.Builder{}
	for i, r := range sn.Text(16) {
		if !compact && i%2 == 0 && i != 0 {
			builder.WriteRune(':')
		}
		builder.WriteRune(r)
	}
	return builder.String()
}

// WasRequestedBefore returns true if the certificate was not requested after the given timestamp.
// Uses the requestedAt annotation of the certificate secret.
// For legacy certificates without requestedAt annotation, this method uses the `notBefore` time of the certificate.
// Let's Encrypt sets the `notBefore` time one hour in the past of request, here it is checked if the `notBefore` time is
// more than 61 minutes in the past of the given timestamp (30 seconds are added for robustness, e.g. possible time drift)
func WasRequestedBefore(cert *x509.Certificate, requestedAt *time.Time, timestamp time.Time) bool {
	if requestedAt != nil {
		return timestamp.After(*requestedAt)
	}
	return timestamp.After(cert.NotBefore.Add(1*time.Hour + 30*time.Second))
}

// IsValidNow returns true if the certificate is still valid
func IsValidNow(cert *x509.Certificate) bool {
	return !time.Now().After(cert.NotAfter)
}

// LookupSerialNumber loads secret to extract the serial number.
func LookupSerialNumber(res resources.Interface, ref *corev1.SecretReference) (string, error) {
	secret := &corev1.Secret{}
	secret.SetNamespace(ref.Namespace)
	secret.SetName(ref.Name)
	_, err := res.GetInto1(secret)
	if err != nil {
		return "", err
	}

	cert, err := legobridge.DecodeCertificateFromSecretData(secret.Data)
	if err != nil {
		return "", err
	}
	return SerialNumberToString(cert.SerialNumber, false), nil
}

// ValidateEmailAddresses checks if the provided email addresses are valid.
func ValidateEmailAddresses(emails []string) error {
	if len(emails) == 0 {
		return nil
	}
	for _, email := range emails {
		if _, err := mail.ParseAddress(email); err != nil {
			return fmt.Errorf("invalid email address: %s, error: %w", email, err)
		}
	}
	return nil
}

// ParseIPAddresses parses a list of IP addresses and returns a slice of net.IP objects.
func ParseIPAddresses(ips []string) ([]net.IP, error) {
	if len(ips) == 0 {
		return nil, nil
	}
	var parsedIPs []net.IP
	for _, ip := range ips {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			return nil, fmt.Errorf("invalid IP address: %s", ip)
		}
		parsedIPs = append(parsedIPs, parsedIP)
	}
	return parsedIPs, nil
}

// ParseURIs parses a list of URIs and returns a slice of parsed *url.URL objects.
func ParseURIs(uris []string) ([]*url.URL, error) {
	if len(uris) == 0 {
		return nil, nil
	}
	var parsedURIs []*url.URL
	for _, uri := range uris {
		parsedURI, err := url.Parse(uri)
		if err != nil {
			return nil, fmt.Errorf("invalid URI: %s, error: %w", uri, err)
		}
		if parsedURI.Scheme == "" {
			return nil, fmt.Errorf("invalid URI: %s, scheme is missing", uri)
		}
		parsedURIs = append(parsedURIs, parsedURI)
	}
	return parsedURIs, nil
}

func hasMultipleIssuerTypes(issuer *api.Issuer) bool {
	count := 0
	if issuer.Spec.SelfSigned != nil {
		count++
	}
	if issuer.Spec.ACME != nil {
		count++
	}
	if issuer.Spec.CA != nil {
		count++
	}
	return count > 1
}

/*
 * SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package legobridge

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/gardener/controller-manager-library/pkg/resources"
	jks "github.com/pavlo-v-chernykh/keystore-go/v4"
	corev1 "k8s.io/api/core/v1"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	certv1alpha1 "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
)

const (
	// PKCS12SecretKey is the name of the data entry in the Secret resource used to store the p12 file.
	PKCS12SecretKey = "keystore.p12"
	// PKCS12TruststoreKey is the name of the data entry in the Secret resource for PKCS12 containing Certificate Authority
	PKCS12TruststoreKey = "truststore.p12"

	// JKSSecretKey is the name of the data entry in the Secret resource used to store the jks file.
	JKSSecretKey = "keystore.jks" // #nosec G101 -- this is no credential
	// JKSTruststoreKey is the name of the data entry in the Secret resource for JKS containing Certificate Authority
	JKSTruststoreKey = "truststore.jks"
)

// RemoveKeystoresFromSecret removes all keystore data entries.
func RemoveKeystoresFromSecret(secret *corev1.Secret) {
	if secret == nil || secret.Data == nil {
		return
	}

	// make sure that secret doesn't contain keystores data fields
	for _, key := range []string{PKCS12SecretKey, PKCS12TruststoreKey, JKSSecretKey, JKSTruststoreKey} {
		delete(secret.Data, key)
	}
}

// AddKeystoresToSecret adds keystore data entries in the secret if requested.
func AddKeystoresToSecret(secretResources resources.Interface, secret *corev1.Secret, keystores *certv1alpha1.CertificateKeystores) error {
	_, err := updateKeystoresToSecret(secretResources, secret, keystores, false)
	return err
}

// UpdateKeystoresToSecret adds, updates, or deletes keystore data entries in the secret.
// Return value `modified` is true if the secret was changed.
func UpdateKeystoresToSecret(secretResources resources.Interface, secret *corev1.Secret, keystores *certv1alpha1.CertificateKeystores) (modified bool, err error) {
	return updateKeystoresToSecret(secretResources, secret, keystores, true)
}

func updateKeystoresToSecret(secretResources resources.Interface, secret *corev1.Secret, keystores *certv1alpha1.CertificateKeystores, keepExisting bool) (modified bool, err error) {
	var jks *certv1alpha1.JKSKeystore
	var pkcs12 *certv1alpha1.PKCS12Keystore
	if keystores != nil {
		jks = keystores.JKS
		pkcs12 = keystores.PKCS12
	}
	if err = updateJKSKeystore(secretResources, secret, jks, keepExisting, &modified); err != nil {
		return
	}
	if err = updatePKCS12Keystore(secretResources, secret, pkcs12, keepExisting, &modified); err != nil {
		return
	}
	return
}

// updateJKSKeystore updates `keystore.jks` and `truststore.jks` data entries to the secret or removes them
// if not requested anymore
func updateJKSKeystore(secretResources resources.Interface, secret *corev1.Secret, jksKeystore *certv1alpha1.JKSKeystore,
	keepExisting bool, modified *bool,
) error {
	if jksKeystore == nil || !jksKeystore.Create {
		update(secret, JKSTruststoreKey, nil, modified)
		update(secret, JKSSecretKey, nil, modified)
		return nil
	}

	cert := SecretDataToCertificates(secret.Data)
	needsTruststore := len(cert.IssuerCertificate) > 0
	if keepExisting &&
		needsTruststore == (len(secret.Data[JKSTruststoreKey]) > 0) &&
		len(secret.Data[JKSSecretKey]) > 0 {
		// data entries already set, done
		return nil
	}

	password, err := loadPassword(secretResources.Namespace(secret.Namespace), jksKeystore.PasswordSecretRef)
	if err != nil {
		return fmt.Errorf("loading JKS password from data key %s of secret %s/%s failed: %w",
			jksKeystore.PasswordSecretRef.Key, secret.Namespace, jksKeystore.PasswordSecretRef.SecretName, err)
	}

	var truststore []byte
	if needsTruststore {
		truststore, err = encodeJKSTruststore(password, cert.IssuerCertificate)
		if err != nil {
			return fmt.Errorf("encoding JKS truststore failed: %w", err)
		}
	}
	update(secret, JKSTruststoreKey, truststore, modified)
	keystore, err := encodeJKSKeystore(password, cert.PrivateKey, cert.Certificate, cert.IssuerCertificate)
	if err != nil {
		return fmt.Errorf("encoding JKS keystore failed: %w", err)
	}
	update(secret, JKSSecretKey, keystore, modified)
	return nil
}

// updatePKCS12Keystore updates `keystore.p12` and `truststore.p12` data entries to the secret or removes them
// if not requested anymore
func updatePKCS12Keystore(secretResources resources.Interface, secret *corev1.Secret, pkcs12Keystore *certv1alpha1.PKCS12Keystore,
	keepExisting bool, modified *bool,
) error {
	if pkcs12Keystore == nil || !pkcs12Keystore.Create {
		update(secret, PKCS12TruststoreKey, nil, modified)
		update(secret, PKCS12SecretKey, nil, modified)
		return nil
	}

	cert := SecretDataToCertificates(secret.Data)
	needsTruststore := len(cert.IssuerCertificate) > 0
	if keepExisting &&
		needsTruststore == (len(secret.Data[PKCS12TruststoreKey]) > 0) &&
		len(secret.Data[PKCS12SecretKey]) > 0 {
		// data entries already set, done
		return nil
	}

	password, err := loadPassword(secretResources.Namespace(secret.Namespace), pkcs12Keystore.PasswordSecretRef)
	if err != nil {
		return fmt.Errorf("loading PKCS#12 password from data key %s of secret %s/%s failed: %w",
			pkcs12Keystore.PasswordSecretRef.Key, secret.Namespace, pkcs12Keystore.PasswordSecretRef.SecretName, err)
	}

	var truststore []byte
	if needsTruststore {
		truststore, err = encodePKCS12Truststore(password, cert.IssuerCertificate)
		if err != nil {
			return fmt.Errorf("encoding PKCS#12 truststore failed: %w", err)
		}
	}
	update(secret, PKCS12TruststoreKey, truststore, modified)
	keystore, err := encodePKCS12Keystore(password, cert.PrivateKey, cert.Certificate, cert.IssuerCertificate)
	if err != nil {
		return fmt.Errorf("encoding JKS keystore failed: %w", err)
	}
	update(secret, PKCS12SecretKey, keystore, modified)
	return nil
}

func update(secret *corev1.Secret, key string, value []byte, modified *bool) {
	if value == nil {
		if len(secret.Data[key]) > 0 {
			delete(secret.Data, key)
			*modified = true
		}
		return
	}

	if bytes.Equal(value, secret.Data[key]) {
		return
	}
	secret.Data[key] = value
	*modified = true
}

func loadPassword(namespacedSecretResource resources.Namespaced, passwordSecretRef certv1alpha1.SecretKeySelector) ([]byte, error) {
	obj, err := namespacedSecretResource.Get(passwordSecretRef.SecretName)
	if err != nil {
		return nil, err
	}
	data := obj.Data().(*corev1.Secret).Data
	if data == nil || data[passwordSecretRef.Key] == nil {
		return nil, fmt.Errorf("key %s not found in secret", passwordSecretRef.Key)
	}
	return data[passwordSecretRef.Key], nil
}

// the following functions are based on code from https://github.com/cert-manager/cert-manager/blob/2db62c21c337cb5af3ea9dce1cbc0b69cfc7c509/pkg/controller/certificates/issuing/internal/keystore.go

// encodePKCS12Keystore will encode a PKCS12 keystore using the password provided.
// The key, certificate and CA data must be provided in PKCS1 or PKCS8 PEM format.
// If the certificate data contains multiple certificates, the first will be used
// as the keystores 'certificate' and the remaining certificates will be prepended
// to the list of CAs in the resulting keystore.
func encodePKCS12Keystore(password []byte, rawKey []byte, certPem []byte, caPem []byte) ([]byte, error) {
	key, err := pki.DecodePrivateKeyBytes(rawKey)
	if err != nil {
		return nil, err
	}
	certs, err := pki.DecodeX509CertificateChainBytes(certPem)
	if err != nil {
		return nil, err
	}
	var cas []*x509.Certificate
	if len(caPem) > 0 {
		cas, err = pki.DecodeX509CertificateChainBytes(caPem)
		if err != nil {
			return nil, err
		}
	}
	// prepend the certificate chain to the list of certificates as the PKCS12
	// library only allows setting a single certificate.
	if len(certs) > 1 {
		cas = append(certs[1:], cas...)
	}
	return pkcs12.Encode(rand.Reader, key, certs[0], cas, string(password))
}

func encodePKCS12Truststore(password []byte, caPem []byte) ([]byte, error) {
	ca, err := pki.DecodeX509CertificateBytes(caPem)
	if err != nil {
		return nil, err
	}

	cas := []*x509.Certificate{ca}
	return pkcs12.EncodeTrustStore(rand.Reader, cas, string(password))
}

func encodeJKSKeystore(password []byte, rawKey []byte, certPem []byte, caPem []byte) ([]byte, error) {
	// encode the private key to PKCS8
	key, err := pki.DecodePrivateKeyBytes(rawKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	// encode the certificate chain
	chain, err := pki.DecodeX509CertificateChainBytes(certPem)
	if err != nil {
		return nil, err
	}
	certs := make([]jks.Certificate, len(chain))
	for i, cert := range chain {
		certs[i] = jks.Certificate{
			Type:    "X509",
			Content: cert.Raw,
		}
	}

	ks := jks.New()
	if err := ks.SetPrivateKeyEntry("certificate", jks.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       keyDER,
		CertificateChain: certs,
	}, password); err != nil {
		return nil, err
	}

	// add the CA certificate, if set
	if len(caPem) > 0 {
		ca, err := pki.DecodeX509CertificateBytes(caPem)
		if err != nil {
			return nil, err
		}
		if err := ks.SetTrustedCertificateEntry("ca", jks.TrustedCertificateEntry{
			CreationTime: time.Now(),
			Certificate: jks.Certificate{
				Type:    "X509",
				Content: ca.Raw,
			},
		},
		); err != nil {
			return nil, err
		}
	}

	buf := &bytes.Buffer{}
	if err := ks.Store(buf, password); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeJKSTruststore(password []byte, caPem []byte) ([]byte, error) {
	ca, err := pki.DecodeX509CertificateBytes(caPem)
	if err != nil {
		return nil, err
	}

	ks := jks.New()
	if err := ks.SetTrustedCertificateEntry("ca", jks.TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate: jks.Certificate{
			Type:    "X509",
			Content: ca.Raw,
		},
	},
	); err != nil {
		return nil, err
	}

	buf := &bytes.Buffer{}
	if err := ks.Store(buf, password); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

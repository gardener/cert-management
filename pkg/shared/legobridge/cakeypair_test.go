/*
 * SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package legobridge

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
)

var _ = Describe("PKI Helpers", func() {
	Context("CAKeyPairFromSecretData", func() {
		It("works for ec key", func() {
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			Expect(err).To(Succeed())
			keyBytes, err := x509.MarshalECPrivateKey(priv)
			Expect(err).To(Succeed())
			data, err := createCertificate(priv, priv.Public(), "EC PRIVATE KEY", keyBytes)
			Expect(err).To(Succeed())

			_, err = CAKeyPairFromSecretData(data)
			Expect(err).To(Succeed())
		})

		It("works for PKCS1 rsa key", func() {
			priv, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).To(Succeed())
			keyBytes := x509.MarshalPKCS1PrivateKey(priv)
			data, err := createCertificate(priv, priv.Public(), "RSA PRIVATE KEY", keyBytes)
			Expect(err).To(Succeed())

			_, err = CAKeyPairFromSecretData(data)
			Expect(err).To(Succeed())
		})

		It("works for PKCS8 rsa key", func() {
			priv, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).To(Succeed())
			keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
			Expect(err).To(Succeed())
			data, err := createCertificate(priv, priv.Public(), "PRIVATE KEY", keyBytes)
			Expect(err).To(Succeed())

			_, err = CAKeyPairFromSecretData(data)
			Expect(err).To(Succeed())
		})

		It("returns error if TLSCertKey is missing", func() {
			data := createCertificateFromRSAKey()
			var err error

			By("Removing the TLSCertKey")
			delete(data, corev1.TLSCertKey)

			_, err = CAKeyPairFromSecretData(data)
			Expect(err).To(MatchError("`tls.crt` data not found in secret"))
		})

		It("returns error if TLSCertKey is empty", func() {
			data := createCertificateFromRSAKey()
			var err error

			By("Removing the TLSCertKey data")
			data[corev1.TLSCertKey] = []byte{}

			_, err = CAKeyPairFromSecretData(data)
			Expect(err).To(MatchError("decoding pem for tls.crt from request secret failed"))
		})

		It("returns error if TLSPrivateKeyKey is missing", func() {
			data := createCertificateFromRSAKey()
			var err error

			By("Removing the TLSPrivateKeyKey")
			delete(data, corev1.TLSPrivateKeyKey)

			_, err = CAKeyPairFromSecretData(data)
			Expect(err).To(MatchError("`tls.key` data not found in secret"))
		})

		It("returns error if TLSPrivateKeyKey is empty", func() {
			data := createCertificateFromRSAKey()
			var err error

			By("Removing the TLSPrivateKeyKey data")
			data[corev1.TLSPrivateKeyKey] = []byte{}

			_, err = CAKeyPairFromSecretData(data)
			Expect(err).To(MatchError("decoding pem block for private key failed"))
		})
	})
})

func createCertificateFromRSAKey() map[string][]byte {
	By("Creating a certificate")
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	ExpectWithOffset(1, err).To(Succeed())
	keyBytes := x509.MarshalPKCS1PrivateKey(priv)
	data, err := createCertificate(priv, priv.Public(), "RSA PRIVATE KEY", keyBytes)
	ExpectWithOffset(1, err).To(Succeed())

	return data
}

func createCertificate(privKey crypto.PrivateKey, pubKey crypto.PublicKey, header string, privKeyBytes []byte) (map[string][]byte, error) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1234),
		Subject:               pkix.Name{CommonName: "example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: header, Bytes: privKeyBytes})
	return map[string][]byte{
		corev1.TLSCertKey:       certPEM,
		corev1.TLSPrivateKeyKey: keyPEM,
	}, nil
}

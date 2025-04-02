// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package legobridge

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/utils/ptr"
)

var _ = Describe("PKI", func() {
	Context("#newSelfSignedCertInPEMFormat", func() {
		It("returns an error with empty input", func() {
			_, _, err := newSelfSignedCertInPEMFormat(ObtainInput{}, x509.RSA, 2048)
			Expect(err).To(HaveOccurred())
		})

		It("returns an error when no common name is set", func() {
			input := ObtainInput{Duration: ptr.To(time.Hour)}
			_, _, err := newSelfSignedCertInPEMFormat(input, x509.RSA, 2048)
			Expect(err).To(MatchError("common name must be set"))
		})

		It("returns an error when no duration is set", func() {
			input := ObtainInput{CommonName: ptr.To("test-common-name")}
			_, _, err := newSelfSignedCertInPEMFormat(input, x509.RSA, 2048)
			Expect(err).To(MatchError("duration must be set"))
		})

		It("should be able to create a self-signed certificate", func() {
			By("Creating a self-signed certificate")
			keySize := 2048
			duration := ptr.To(90 * 24 * time.Hour)
			expectedNotBefore := time.Now()
			expectedNotAfter := expectedNotBefore.Add(*duration)
			input := ObtainInput{
				CommonName: ptr.To("test-common-name"),
				DNSNames:   []string{"test-dns-name"},
				Duration:   duration,
			}
			certPEM, certPrivateKeyPEM, err := newSelfSignedCertInPEMFormat(input, x509.RSA, keySize)
			Expect(err).NotTo(HaveOccurred())
			Expect(certPEM).NotTo(BeNil())
			Expect(certPEM).NotTo(BeEmpty())
			Expect(certPrivateKeyPEM).NotTo(BeNil())
			Expect(certPrivateKeyPEM).NotTo(BeEmpty())

			By("Decoding the certificate")
			p, _ := pem.Decode(certPEM)
			Expect(p).NotTo(BeNil())
			Expect(p.Bytes).NotTo(BeEmpty())

			By("Parsing the certificate")
			cert, err := x509.ParseCertificate(p.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(cert).NotTo(BeNil())
			Expect(cert.Subject.CommonName).To(Equal(*input.CommonName))
			Expect(cert.DNSNames).To(ContainElement(input.DNSNames[0]))
			Expect(cert.IsCA).To(BeTrue())
			Expect(cert.NotBefore).To(BeTemporally("~", expectedNotBefore, 10*time.Second))
			Expect(cert.NotAfter).To(BeTemporally("~", expectedNotAfter, 10*time.Second))

			By("Decoding the certificate private key")
			p, _ = pem.Decode(certPrivateKeyPEM)
			Expect(p).NotTo(BeNil())
			Expect(p.Bytes).NotTo(BeEmpty())

			By("Parsing the certificate private key")
			privateKey, err := x509.ParsePKCS1PrivateKey(p.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(privateKey).NotTo(BeNil())
			Expect(privateKey.Size()).To(Equal(keySize / 8))
		})
	})

	Context("#generatePrivateKey", func() {
		DescribeTable("should generate a private key of the expected type and size",
			func(keyType certcrypto.KeyType, expectedKeySize int) {
				key, err := generatePrivateKey(keyType)
				Expect(err).NotTo(HaveOccurred())
				Expect(key).NotTo(BeNil())
				Expect(pubKeySize(key.Public())).To(Equal(expectedKeySize))
				switch keyType {
				case certcrypto.EC256, certcrypto.EC384:
					Expect(key).To(BeAssignableToTypeOf(&ecdsa.PrivateKey{}))
				case certcrypto.RSA2048, certcrypto.RSA3072, certcrypto.RSA4096, certcrypto.RSA8192:
					Expect(key).To(BeAssignableToTypeOf(&rsa.PrivateKey{}))
				}
			},
			Entry("ECDSA 256", certcrypto.EC256, 256),
			Entry("ECDSA 384", certcrypto.EC384, 384),
			Entry("RSA 2048", certcrypto.RSA2048, 2048),
			Entry("RSA 3072", certcrypto.RSA3072, 3072),
			Entry("RSA 4096", certcrypto.RSA4096, 4096),
		)

		It("should fail on an invalid key type", func() {
			key, err := generatePrivateKey("invalid")
			Expect(err).To(HaveOccurred())
			Expect(key).To(BeNil())
		})
	})

	Context("#getPublicKeyAlgorithm", func() {
		It("should recognize ECDSA", func() {
			Expect(getPublicKeyAlgorithm(&ecdsa.PrivateKey{})).To(Equal(x509.ECDSA))
		})

		It("should recognize RSA", func() {
			Expect(getPublicKeyAlgorithm(&rsa.PrivateKey{})).To(Equal(x509.RSA))
		})

		// ED25519 is a valid algorithm but currently not supported by cert-management.
		It("should return unknown for ED25519", func() {
			Expect(getPublicKeyAlgorithm(&ed25519.PrivateKey{})).To(Equal(x509.UnknownPublicKeyAlgorithm))
		})
	})
})

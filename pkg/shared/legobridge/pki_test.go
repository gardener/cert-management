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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/utils/ptr"
)

var _ = Describe("PKI", func() {
	Context("#NewSelfSignedCertInPEMFormat", func() {
		It("returns an error with empty input", func() {
			_, _, err := NewSelfSignedCertInPEMFormat(ObtainInput{})
			Expect(err).To(HaveOccurred())
		})

		It("returns an error when no common name is set", func() {
			input := ObtainInput{Duration: ptr.To(time.Hour)}
			_, _, err := NewSelfSignedCertInPEMFormat(input)
			Expect(err).To(MatchError("common name must be set"))
		})

		It("returns an error when no duration is set", func() {
			input := ObtainInput{CommonName: ptr.To("test-common-name")}
			_, _, err := NewSelfSignedCertInPEMFormat(input)
			Expect(err).To(MatchError("duration must be set"))
		})

		DescribeTable("should be able to create a self-signed certificate",
			func(usePKCS8 bool) {
				By("Creating a self-signed certificate")
				keySize := 2048
				duration := ptr.To(90 * 24 * time.Hour)
				expectedNotBefore := time.Now()
				expectedNotAfter := expectedNotBefore.Add(*duration)
				input := ObtainInput{
					CommonName: ptr.To("test-common-name"),
					DNSNames:   []string{"test-dns-name"},
					Duration:   duration,
					KeySpec:    KeySpec{KeyType: RSA2048, UsePKCS8: usePKCS8},
				}
				certPEM, certPrivateKeyPEM, err := NewSelfSignedCertInPEMFormat(input)
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

				By("Decoding and parsing the certificate private key")
				privateKey, err := BytesToPrivateKey(certPrivateKeyPEM)
				Expect(err).NotTo(HaveOccurred())
				Expect(privateKey).NotTo(BeNil())
				pk, ok := privateKey.(*rsa.PrivateKey)
				Expect(ok).To(BeTrue())
				Expect(pk.Size()).To(Equal(keySize / 8))
			},
			Entry("with PKCS1 format", false),
			Entry("with PKCS8 format", true),
		)
	})

	Context("#GenerateKeyFromSpec", func() {
		DescribeTable("should generate a private key of the expected type and size",
			func(keyType KeyType, usePKCS8 bool, expectedKeySize int) {
				key, pem, err := GenerateKeyFromSpec(KeySpec{KeyType: keyType, UsePKCS8: usePKCS8})
				Expect(err).NotTo(HaveOccurred())
				Expect(key).NotTo(BeNil())
				Expect(pubKeySize(key.Public())).To(Equal(expectedKeySize))
				switch keyType {
				case EC256, EC384:
					Expect(key).To(BeAssignableToTypeOf(&ecdsa.PrivateKey{}))
				case RSA2048, RSA3072, RSA4096:
					Expect(key).To(BeAssignableToTypeOf(&rsa.PrivateKey{}))
				}
				if usePKCS8 {
					Expect(string(pem)).To(ContainSubstring("BEGIN PRIVATE KEY"))
				} else {
					switch keyType {
					case EC256, EC384:
						Expect(string(pem)).To(ContainSubstring("BEGIN EC PRIVATE KEY"))
					case RSA2048, RSA3072, RSA4096:
						Expect(string(pem)).To(ContainSubstring("BEGIN RSA PRIVATE KEY"))
					}
				}
			},
			Entry("ECDSA 256", EC256, false, 256),
			Entry("ECDSA 384", EC384, false, 384),
			Entry("RSA 2048", RSA2048, false, 2048),
			Entry("RSA 3072", RSA3072, false, 3072),
			Entry("RSA 4096", RSA4096, false, 4096),
			Entry("ECDSA 256 with PKCS#8", EC256, true, 256),
			Entry("RSA 2048 with PKCS#8", RSA2048, true, 2048),
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

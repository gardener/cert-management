/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package legobridge

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
)

var _ = Describe("Certificate", func() {
	DescribeTable("KeyType conversion",
		func(keyType certcrypto.KeyType, algorithm api.PrivateKeyAlgorithm, size int) {
			defaults, err := NewCertificatePrivateKeyDefaults(api.RSAKeyAlgorithm, 2048, 256)
			Expect(err).ToNot(HaveOccurred())

			var key *api.CertificatePrivateKey
			if len(algorithm) > 0 {
				key = &api.CertificatePrivateKey{Algorithm: ptr.To(algorithm)}
			}
			if size > 0 {
				if key == nil {
					key = &api.CertificatePrivateKey{}
				}
				key.Size = ptr.To(api.PrivateKeySize(size))
			}
			actualKeyType, err := defaults.ToKeyType(key)
			if keyType == "" {
				Expect(err).To(HaveOccurred())
			} else {
				Expect(err).ToNot(HaveOccurred())
				Expect(actualKeyType).To(Equal(keyType))
				actualKeyType, err = defaults.ToKeyType(FromKeyType(keyType))
				Expect(err).ToNot(HaveOccurred())
				Expect(actualKeyType).To(Equal(keyType))
			}
		},
		Entry("default", certcrypto.RSA2048, api.PrivateKeyAlgorithm(""), 0),
		Entry("RSA from empty config", certcrypto.RSA2048, api.RSAKeyAlgorithm, 0),
		Entry("RSA2048", certcrypto.RSA2048, api.RSAKeyAlgorithm, 2048),
		Entry("RSA3072", certcrypto.RSA3072, api.RSAKeyAlgorithm, 3072),
		Entry("RSA4096", certcrypto.RSA4096, api.RSAKeyAlgorithm, 4096),
		Entry("ECDSA with default size", certcrypto.EC256, api.ECDSAKeyAlgorithm, 0),
		Entry("EC256", certcrypto.EC256, api.ECDSAKeyAlgorithm, 256),
		Entry("EC384", certcrypto.EC384, api.ECDSAKeyAlgorithm, 384),
		Entry("RSA with wrong size", certcrypto.KeyType(""), api.RSAKeyAlgorithm, 8192),
		Entry("ECDSA with wrong size", certcrypto.KeyType(""), api.ECDSAKeyAlgorithm, 511),
	)

	Describe("NewCertificatePrivateKeyDefaults", func() {
		It("should return an error for unknown algorithm", func() {
			_, err := NewCertificatePrivateKeyDefaults(api.PrivateKeyAlgorithm("NotAnAlgorithm"), api.PrivateKeySize(0), api.PrivateKeySize(0))
			Expect(err).To(MatchError("invalid algoritm: 'NotAnAlgorithm' (allowed values: 'RSA' and 'ECDSA')"))
		})

		It("should return an error for invalid RSA key size", func() {
			_, err := NewCertificatePrivateKeyDefaults(api.PrivateKeyAlgorithm("RSA"), api.PrivateKeySize(1234), api.PrivateKeySize(0))
			Expect(err).To(MatchError("invalid RSA private key size: 1234 (allowed values: 2048, 3072, 4096)"))
		})

		It("should return an error for invalid ECDSA key size", func() {
			_, err := NewCertificatePrivateKeyDefaults(api.PrivateKeyAlgorithm("RSA"), api.PrivateKeySize(2048), api.PrivateKeySize(1234))
			Expect(err).To(MatchError("invalid ECDSA private key size: 1234 (allowed values: 256, 384)"))
		})
	})

	It("obtainForDomains should fail with unknown key type", func() {
		_, err := obtainForDomains(nil, []string{}, ObtainInput{KeyType: "SomeUnknownKeyType"})
		Expect(err).To(MatchError("invalid KeyType: SomeUnknownKeyType"))
	})

	Context("#newSelfSignedCertFromCSRinPEMFormat", func() {
		It("should fail decoding the CSR with empty input", func() {
			_, _, err := newSelfSignedCertFromCSRinPEMFormat(ObtainInput{})
			Expect(err).To(MatchError("decoding CSR failed"))
		})

		It("should fail decoding an invalid CSR", func() {
			_, _, err := newSelfSignedCertFromCSRinPEMFormat(ObtainInput{CSR: []byte("invalid")})
			Expect(err).To(MatchError("decoding CSR failed"))
		})

		Context("with a valid CSR", func() {
			var input ObtainInput

			BeforeEach(func() {
				input = ObtainInput{CSR: _createCSR()}
			})

			It("should fail when no duration is set", func() {
				_, _, err := newSelfSignedCertFromCSRinPEMFormat(input)
				Expect(err).To(MatchError("duration must be set"))
			})

			It("should succeed when the duration is set", func() {
				input.Duration = ptr.To(time.Hour)
				cert, key, err := newSelfSignedCertFromCSRinPEMFormat(input)
				Expect(err).NotTo(HaveOccurred())
				Expect(cert).NotTo(BeNil())
				Expect(key).NotTo(BeNil())
			})
		})
	})

	Context("#newSelfSignedCertFromInput", func() {
		It("should fail with empty input", func() {
			_, err := newSelfSignedCertFromInput(ObtainInput{})
			Expect(err).To(MatchError("invalid key type: ''"))
		})

		It("should create a self-signed certificate from the input", func() {
			input := ObtainInput{KeyType: certcrypto.RSA2048, Duration: ptr.To(time.Hour), CommonName: ptr.To("test-common-name")}
			cert, err := newSelfSignedCertFromInput(input)
			Expect(err).NotTo(HaveOccurred())
			Expect(cert).NotTo(BeNil())
			assertRSAPrivateKeySize(cert.PrivateKey, 2048)
		})

		It("should create a self-signed certificate from a CSR", func() {
			input := ObtainInput{CSR: _createCSR(), Duration: ptr.To(time.Hour)}
			cert, err := newSelfSignedCertFromInput(input)
			Expect(err).NotTo(HaveOccurred())
			Expect(cert).NotTo(BeNil())
			assertRSAPrivateKeySize(cert.PrivateKey, 2048)
		})

		It("should prioritize a CSR over the input key type", func() {
			input := ObtainInput{CSR: _createCSR(), KeyType: certcrypto.EC256, Duration: ptr.To(time.Hour)}
			cert, err := newSelfSignedCertFromInput(input)
			Expect(err).NotTo(HaveOccurred())
			Expect(cert).NotTo(BeNil())
			assertRSAPrivateKeySize(cert.PrivateKey, 2048)
		})
	})

	Describe("Certificate/SecretData conversion", func() {
		It("CertificateToSecretData should return correct SecretData", func() {
			certificates := &certificate.Resource{
				Certificate:       []byte{0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01},
				PrivateKey:        []byte{0x3a, 0x4e, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f},
				IssuerCertificate: []byte{0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f, 0x1f},
			}

			secretData := CertificatesToSecretData(certificates)

			Expect(secretData[corev1.TLSCertKey]).To(Equal(certificates.Certificate))
			Expect(secretData[corev1.TLSPrivateKeyKey]).To(Equal(certificates.PrivateKey))
			Expect(secretData[TLSCAKey]).To(Equal(certificates.IssuerCertificate))
		})

		It("SecretDataToCertificates should return correct Certificates", func() {
			secretData := map[string][]byte{}
			secretData[corev1.TLSCertKey] = []byte{0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01}
			secretData[corev1.TLSPrivateKeyKey] = []byte{0x3a, 0x4e, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f}
			secretData[TLSCAKey] = []byte{0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f, 0x1f}

			certificates := SecretDataToCertificates(secretData)

			Expect(certificates.Certificate).To(Equal(secretData[corev1.TLSCertKey]))
			Expect(certificates.PrivateKey).To(Equal(secretData[corev1.TLSPrivateKeyKey]))
			Expect(certificates.IssuerCertificate).To(Equal(secretData[TLSCAKey]))
		})
	})
})

func assertRSAPrivateKeySize(keyMaterial []byte, expectedBits int) {
	block, rest := pem.Decode(keyMaterial)
	ExpectWithOffset(1, rest).To(BeEmpty())

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	ExpectWithOffset(1, privateKey.Size()).To(Equal(expectedBits / 8))
}

func _createCSR() []byte {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})
}

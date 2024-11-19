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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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

			It("should fail when no duration is set", func() {
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
			Expect(cap(cert.PrivateKey)).To(Equal(2048))
		})

		It("should create a self-signed certificate from a CSR", func() {
			input := ObtainInput{CSR: _createCSR(), Duration: ptr.To(time.Hour)}
			cert, err := newSelfSignedCertFromInput(input)
			Expect(err).NotTo(HaveOccurred())
			Expect(cert).NotTo(BeNil())
			Expect(cap(cert.PrivateKey)).To(Equal(2048))
		})

		It("should prioritize a CSR over the input key type", func() {
			input := ObtainInput{CSR: _createCSR(), KeyType: certcrypto.EC256, Duration: ptr.To(time.Hour)}
			cert, err := newSelfSignedCertFromInput(input)
			Expect(err).NotTo(HaveOccurred())
			Expect(cert).NotTo(BeNil())
			Expect(cap(cert.PrivateKey)).To(Equal(2048))
		})
	})
})

func _createCSR() []byte {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})
}

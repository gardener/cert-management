// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package legobridge

import (
	"crypto/x509"
	"encoding/pem"
	"time"

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

		It("should be able to create a self signed certificate", func() {
			duration := ptr.To(90 * 24 * time.Hour)
			expectedNotBefore := time.Now()
			expectedNotAfter := expectedNotBefore.Add(*duration)
			input := ObtainInput{
				CommonName: ptr.To("test-common-name"),
				DNSNames:   []string{"test-dns-name"},
				Duration:   duration,
			}
			certPEM, certPrivateKeyPEM, err := newSelfSignedCertInPEMFormat(input, x509.RSA, 2048)
			Expect(err).NotTo(HaveOccurred())
			Expect(certPEM).NotTo(BeNil())
			Expect(certPEM).NotTo(BeEmpty())
			Expect(certPrivateKeyPEM).NotTo(BeNil())
			Expect(certPrivateKeyPEM).NotTo(BeEmpty())

			p, _ := pem.Decode(certPEM)
			Expect(p).NotTo(BeNil())
			Expect(p.Bytes).NotTo(BeEmpty())

			cert, err := x509.ParseCertificate(p.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(cert).NotTo(BeNil())
			Expect(cert.Subject.CommonName).To(Equal(*input.CommonName))
			Expect(cert.DNSNames).To(ContainElement(input.DNSNames[0]))
			Expect(cert.IsCA).To(BeTrue())
			Expect(cert.NotBefore).To(BeTemporally("~", expectedNotBefore, time.Second))
			Expect(cert.NotAfter).To(BeTemporally("~", expectedNotAfter, time.Second))

			p, _ = pem.Decode(certPrivateKeyPEM)
			Expect(p).NotTo(BeNil())
			Expect(p.Bytes).NotTo(BeEmpty())

			privateKey, err := x509.ParsePKCS1PrivateKey(p.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(privateKey).NotTo(BeNil())
		})
	})
})

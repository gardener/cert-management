// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package shared_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/cert-management/pkg/cert/utils"
)

var _ = Describe("ExtractCommonNameAnDNSNames", func() {
	var (
		exampleCn  string
		exampleSan []string
		exampleIPs []net.IP
	)

	BeforeEach(func() {
		exampleCn = "example.com"
		exampleSan = []string{"www.example.com", "example.org"}
		exampleIPs = []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1")}
	})

	It("should extract cn, san, and IP addresses if Common Name (cn), Subject Alternative Name (san), and IP Addresses are set", func() {
		csr := _createCSR(exampleCn, exampleSan, exampleIPs)
		cn, san, err := utils.ExtractCommonNameAnDNSNames(csr)
		Expect(err).ToNot(HaveOccurred())
		Expect(*cn).To(Equal(exampleCn))
		Expect(san).To(ContainElements(append(exampleSan, "192.168.1.1", "10.0.0.1")))
	})

	It("should only return the san and IP addresses if Common Name is not set", func() {
		csr := _createCSR("", exampleSan, exampleIPs)
		cn, san, err := utils.ExtractCommonNameAnDNSNames(csr)
		Expect(err).ToNot(HaveOccurred())
		Expect(cn).To(BeNil())
		Expect(san).To(ContainElements(append(exampleSan, "192.168.1.1", "10.0.0.1")))
	})

	It("should fail with an error if CSR is not parseable", func() {
		csr := []byte("invalid csr")
		cn, san, err := utils.ExtractCommonNameAnDNSNames(csr)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError("parsing CSR failed: decoding CSR failed"))
		Expect(cn).To(BeNil())
		Expect(san).To(BeEmpty())
	})
})

func _createCSR(cn string, san []string, ips []net.IP) []byte {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: cn,
		},
		DNSNames:    san,
		IPAddresses: ips,
	}
	csr, _ := x509.CreateCertificateRequest(rand.Reader, template, key)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})
}

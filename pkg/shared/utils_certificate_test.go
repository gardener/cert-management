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

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/shared"
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
		cn, san, err := shared.ExtractCommonNameAnDNSNames(csr)
		Expect(err).ToNot(HaveOccurred())
		Expect(*cn).To(Equal(exampleCn))
		Expect(san).To(ContainElements(append(exampleSan, "192.168.1.1", "10.0.0.1")))
	})

	It("should only return the san and IP addresses if Common Name is not set", func() {
		csr := _createCSR("", exampleSan, exampleIPs)
		cn, san, err := shared.ExtractCommonNameAnDNSNames(csr)
		Expect(err).ToNot(HaveOccurred())
		Expect(cn).To(BeNil())
		Expect(san).To(ContainElements(append(exampleSan, "192.168.1.1", "10.0.0.1")))
	})

	It("should fail with an error if CSR is not parseable", func() {
		csr := []byte("invalid csr")
		cn, san, err := shared.ExtractCommonNameAnDNSNames(csr)
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

var _ = Describe("ExtractCommonNameFromLiteralSubject", func() {
	It("should return the common name when present", func() {
		Expect(shared.ExtractCommonNameFromLiteralSubject("CN=leaf.example.com,O=MyOrg,C=DE")).
			To(HaveValue(Equal("leaf.example.com")))
	})

	It("should return nil when no common name is present", func() {
		Expect(shared.ExtractCommonNameFromLiteralSubject("O=MyOrg,C=DE")).To(BeNil())
	})

	It("should return nil for an unparseable literal subject", func() {
		Expect(shared.ExtractCommonNameFromLiteralSubject("not a valid DN")).To(BeNil())
	})
})

var _ = Describe("ToKeyUsages", func() {
	It("should return valid usages for a comma-separated list", func() {
		result := shared.ToKeyUsages("signing,digital signature,server auth")
		Expect(result).To(ConsistOf(api.UsageSigning, api.UsageDigitalSignature, api.UsageServerAuth))
	})

	It("should ignore unknown usage values", func() {
		result := shared.ToKeyUsages("signing,unknown-usage,server auth")
		Expect(result).To(ConsistOf(api.UsageSigning, api.UsageServerAuth))
	})

	It("should return empty slice for empty string", func() {
		result := shared.ToKeyUsages("")
		Expect(result).To(BeEmpty())
	})

	It("should return empty slice if all values are unknown", func() {
		result := shared.ToKeyUsages("foo,bar,baz")
		Expect(result).To(BeEmpty())
	})

	It("should handle a single valid usage", func() {
		result := shared.ToKeyUsages("client auth")
		Expect(result).To(ConsistOf(api.UsageClientAuth))
	})

	It("should handle usages with spaces in their names", func() {
		result := shared.ToKeyUsages("key encipherment,key agreement")
		Expect(result).To(ConsistOf(api.UsageKeyEncipherment, api.UsageKeyAgreement))
	})
})

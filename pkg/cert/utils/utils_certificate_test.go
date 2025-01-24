// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package utils_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/cert/utils"
)

var _ = Describe("UtilsCertificate", func() {
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

	Describe("ExtractCommonNameAnDNSNames", func() {
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

	Describe("ExtractDomains", func() {
		Context("CommonName or DNSNames are specified", func() {
			It("should return an error if CSR is not nil", func() {
				csr := _createCSR("", nil, nil)
				spec := api.CertificateSpec{
					CommonName: &exampleCn,
					DNSNames:   exampleSan,
					CSR:        csr,
				}

				dnsNames, err := utils.ExtractDomains(&spec)
				Expect(dnsNames).To(BeNil())
				Expect(err).To(MatchError("cannot specify both commonName and csr"))
			})

			It("should return error if there are >= 100 DNSNames", func() {
				for i := 0; i <= 100; i++ {
					exampleSan = append(exampleSan, "example.com")
				}

				spec := api.CertificateSpec{
					CommonName: &exampleCn,
					DNSNames:   exampleSan,
				}

				dnsNames, err := utils.ExtractDomains(&spec)
				Expect(dnsNames).To(BeNil())
				Expect(err).To(MatchError("invalid number of DNS names: 103 (max 99)"))
			})

			It("should return error if the CommonName is longer than 64", func() {
				longCommonName := strings.Repeat("a", 65)
				spec := api.CertificateSpec{
					CommonName: &longCommonName,
					DNSNames:   exampleSan,
				}
				dnsNames, err := utils.ExtractDomains(&spec)
				Expect(dnsNames).To(BeNil())
				Expect(err).To(MatchError("the Common Name is limited to 64 characters (X.509 ASN.1 specification), but first given domain aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa has 65 characters"))
			})

			It("should return the CommonName and DNSName when both are specified", func() {
				spec := api.CertificateSpec{
					CommonName: &exampleCn,
					DNSNames:   exampleSan,
				}

				dnsNames, err := utils.ExtractDomains(&spec)
				Expect(dnsNames).To(Equal(append([]string{exampleCn}, exampleSan...)))
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("Neither CommonName nor DNSNames are specified", func() {
			It("should return error if CSR is not specified either", func() {
				spec := api.CertificateSpec{}
				dnsNames, err := utils.ExtractDomains(&spec)
				Expect(dnsNames).To(BeNil())
				Expect(err).To(MatchError("either domains or csr must be specified"))
			})

			It("should extract the DNSNames from the CSR if CRN is specified and valid", func() {
				csr := _createCSR(exampleCn, exampleSan, exampleIPs)
				spec := api.CertificateSpec{
					CSR: csr,
				}
				dnsNames, err := utils.ExtractDomains(&spec)
				Expect(dnsNames).To(Equal(append([]string{exampleCn}, append(exampleSan, "192.168.1.1", "10.0.0.1")...)))
				Expect(err).NotTo(HaveOccurred())
			})

			It("should return error if CRN is specified and not valid", func() {
				spec := api.CertificateSpec{
					CSR: []byte{},
				}
				dnsNames, err := utils.ExtractDomains(&spec)
				Expect(dnsNames).To(BeNil())
				Expect(err).To(MatchError("parsing CSR failed: decoding CSR failed"))
			})
		})
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

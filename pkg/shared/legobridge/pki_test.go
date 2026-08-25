// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package legobridge

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"time"

	"github.com/cert-manager/cert-manager/pkg/util/pki"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/utils/ptr"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
)

// parseSelfSignedCert creates a self-signed certificate from the input and returns
// the parsed x509 certificate, failing the test on any error.
func parseSelfSignedCert(input ObtainInput) *x509.Certificate {
	_, certPEM, _, err := NewSelfSignedCertInPEMFormat(input)
	Expect(err).NotTo(HaveOccurred())
	p, _ := pem.Decode(certPEM)
	Expect(p).NotTo(BeNil())
	cert, err := x509.ParseCertificate(p.Bytes)
	Expect(err).NotTo(HaveOccurred())
	return cert
}

var _ = Describe("PKI", func() {
	Context("#NewSelfSignedCertInPEMFormat", func() {
		It("returns an error with empty input", func() {
			_, _, _, err := NewSelfSignedCertInPEMFormat(ObtainInput{})
			Expect(err).To(HaveOccurred())
		})

		It("returns an error when no common name or literal subject is set", func() {
			input := ObtainInput{Duration: ptr.To(time.Hour)}
			_, _, _, err := NewSelfSignedCertInPEMFormat(input)
			Expect(err).To(MatchError("common name or literal subject must be set"))
		})

		It("returns an error when no duration is set", func() {
			input := ObtainInput{CommonName: new("test-common-name")}
			_, _, _, err := NewSelfSignedCertInPEMFormat(input)
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
					CommonName: new("test-common-name"),
					DNSNames:   []string{"test-dns-name"},
					Duration:   duration,
					KeySpec:    KeySpec{KeyType: RSA2048, UsePKCS8: usePKCS8},
				}
				subject, certPEM, certPrivateKeyPEM, err := NewSelfSignedCertInPEMFormat(input)
				Expect(err).NotTo(HaveOccurred())
				Expect(subject.CommonName).To(Equal(*input.CommonName))
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

		It("sets the structured subject attributes", func() {
			input := ObtainInput{
				CommonName: new("test-common-name"),
				Duration:   ptr.To(time.Hour),
				KeySpec:    KeySpec{KeyType: RSA2048},
				Subject: &api.X509Subject{
					Organizations:       []string{"org-a", "org-b"},
					Countries:           []string{"DE"},
					OrganizationalUnits: []string{"ou-a"},
					Localities:          []string{"Walldorf"},
					Provinces:           []string{"BW"},
					StreetAddresses:     []string{"Dietmar-Hopp-Allee 16"},
					PostalCodes:         []string{"69190"},
					SerialNumber:        "12345",
				},
			}
			cert := parseSelfSignedCert(input)
			Expect(cert.Subject.CommonName).To(Equal("test-common-name"))
			Expect(cert.Subject.Organization).To(Equal([]string{"org-a", "org-b"}))
			Expect(cert.Subject.Country).To(Equal([]string{"DE"}))
			Expect(cert.Subject.OrganizationalUnit).To(Equal([]string{"ou-a"}))
			Expect(cert.Subject.Locality).To(Equal([]string{"Walldorf"}))
			Expect(cert.Subject.Province).To(Equal([]string{"BW"}))
			Expect(cert.Subject.StreetAddress).To(Equal([]string{"Dietmar-Hopp-Allee 16"}))
			Expect(cert.Subject.PostalCode).To(Equal([]string{"69190"}))
			Expect(cert.Subject.SerialNumber).To(Equal("12345"))
		})

		It("sets the subject from a literal subject", func() {
			input := ObtainInput{
				LiteralSubject: new("CN=foo,O=bar,C=DE"),
				Duration:       ptr.To(time.Hour),
				KeySpec:        KeySpec{KeyType: RSA2048},
			}
			cert := parseSelfSignedCert(input)
			Expect(cert.Subject.CommonName).To(Equal("foo"))
			Expect(cert.Subject.Organization).To(Equal([]string{"bar"}))
			Expect(cert.Subject.Country).To(Equal([]string{"DE"}))
		})

		It("preserves the attribute order and non-structured attributes of a literal subject", func() {
			// The order of RDNs and attribute types without a dedicated pkix.Name field
			// (here: domainComponent / DC) must be preserved verbatim. Go re-marshals the
			// structured pkix.Name fields in its own canonical order and drops unknown
			// attribute types, so the RawSubject of the issued certificate must equal the
			// DER encoding of the requested literal subject exactly.
			literalSubject := "CN=foo,DC=corp,DC=example,DC=com"
			input := ObtainInput{
				LiteralSubject: new(literalSubject),
				Duration:       ptr.To(time.Hour),
				KeySpec:        KeySpec{KeyType: RSA2048},
			}
			cert := parseSelfSignedCert(input)

			expectedRDNs, err := pki.UnmarshalSubjectStringToRDNSequence(literalSubject)
			Expect(err).NotTo(HaveOccurred())
			expectedDER, err := pki.MarshalRDNSequenceToRawDERBytes(expectedRDNs)
			Expect(err).NotTo(HaveOccurred())

			Expect(cert.RawSubject).To(Equal(expectedDER))
			// Round-trip the issued subject back to a string and compare the ordered RDNs.
			actualRDNs, err := pki.UnmarshalRawDerBytesToRDNSequence(cert.RawSubject)
			Expect(err).NotTo(HaveOccurred())
			Expect(actualRDNs).To(Equal(expectedRDNs))
		})

		It("returns an error for an invalid literal subject", func() {
			input := ObtainInput{
				LiteralSubject: new("not a valid DN"),
				Duration:       ptr.To(time.Hour),
				KeySpec:        KeySpec{KeyType: RSA2048},
			}
			_, _, _, err := NewSelfSignedCertInPEMFormat(input)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("literalSubject"))
		})

		It("applies the requested key usages and always includes cert sign", func() {
			input := ObtainInput{
				CommonName: new("test-common-name"),
				Duration:   ptr.To(time.Hour),
				KeySpec:    KeySpec{KeyType: RSA2048},
				Usages:     []api.KeyUsage{api.UsageDigitalSignature, api.UsageClientAuth},
			}
			cert := parseSelfSignedCert(input)
			Expect(cert.KeyUsage & x509.KeyUsageDigitalSignature).NotTo(BeZero())
			Expect(cert.KeyUsage & x509.KeyUsageCertSign).NotTo(BeZero())
			Expect(cert.ExtKeyUsage).To(ConsistOf(x509.ExtKeyUsageClientAuth))
		})

		It("defaults to server auth extended usage when no usages are set", func() {
			input := ObtainInput{
				CommonName: new("test-common-name"),
				Duration:   ptr.To(time.Hour),
				KeySpec:    KeySpec{KeyType: RSA2048},
			}
			cert := parseSelfSignedCert(input)
			Expect(cert.ExtKeyUsage).To(ConsistOf(x509.ExtKeyUsageServerAuth))
			Expect(cert.KeyUsage & x509.KeyUsageCertSign).NotTo(BeZero())
			Expect(cert.KeyUsage & x509.KeyUsageKeyEncipherment).NotTo(BeZero())
		})
	})

	Context("#createCertReq", func() {
		baseInput := func() ObtainInput {
			return ObtainInput{
				CAKeyPair: &TLSKeyPair{Cert: x509.Certificate{}},
				KeySpec:   KeySpec{KeyType: RSA2048},
			}
		}

		It("adds the common name as a DNS SAN for leaf certificates", func() {
			input := baseInput()
			input.CommonName = new("*.ingress.example.com")
			csr, err := createCertReq(input)
			Expect(err).NotTo(HaveOccurred())
			Expect(csr.Subject.CommonName).To(Equal("*.ingress.example.com"))
			Expect(csr.DNSNames).To(ConsistOf("*.ingress.example.com"))
		})

		It("prepends the common name without duplicating an existing DNS name", func() {
			input := baseInput()
			input.CommonName = new("a.example.com")
			input.DNSNames = []string{"b.example.com", "a.example.com"}
			csr, err := createCertReq(input)
			Expect(err).NotTo(HaveOccurred())
			Expect(csr.DNSNames).To(Equal([]string{"b.example.com", "a.example.com"}))
		})

		It("does not add the common name as a SAN for CA certificates", func() {
			input := baseInput()
			input.CommonName = new("Intermediate CA")
			input.IsCA = true
			csr, err := createCertReq(input)
			Expect(err).NotTo(HaveOccurred())
			Expect(csr.DNSNames).To(BeEmpty())
		})

		It("uses the requested structured subject instead of the CA attributes", func() {
			input := baseInput()
			input.CAKeyPair = &TLSKeyPair{Cert: x509.Certificate{Subject: pkix.Name{Organization: []string{"ca-org"}}}}
			input.CommonName = new("leaf.example.com")
			input.Subject = &api.X509Subject{Organizations: []string{"requested-org"}}
			csr, err := createCertReq(input)
			Expect(err).NotTo(HaveOccurred())
			Expect(csr.Subject.CommonName).To(Equal("leaf.example.com"))
			Expect(csr.Subject.Organization).To(Equal([]string{"requested-org"}))
		})

		It("promotes the common name of a literal subject to a DNS SAN for leaf certificates", func() {
			input := baseInput()
			input.LiteralSubject = new("CN=leaf.example.com,O=bar")
			csr, err := createCertReq(input)
			Expect(err).NotTo(HaveOccurred())
			Expect(csr.Subject.CommonName).To(Equal("leaf.example.com"))
			Expect(csr.Subject.Organization).To(Equal([]string{"bar"}))
			Expect(csr.DNSNames).To(ConsistOf("leaf.example.com"))
		})

		It("does not promote the common name of a literal subject for CA certificates", func() {
			input := baseInput()
			input.IsCA = true
			input.LiteralSubject = new("CN=Intermediate CA,O=bar")
			csr, err := createCertReq(input)
			Expect(err).NotTo(HaveOccurred())
			Expect(csr.Subject.CommonName).To(Equal("Intermediate CA"))
			Expect(csr.DNSNames).To(BeEmpty())
		})

		It("preserves the attribute order of a literal subject in the CSR", func() {
			// The DN order must survive CSR creation: RawSubject must hold the DER
			// encoding of the requested literal subject in the requested order.
			literalSubject := "CN=leaf.example.com,DC=corp,DC=example,DC=com,O=bar,C=DE"
			input := baseInput()
			input.LiteralSubject = new(literalSubject)
			csr, err := createCertReq(input)
			Expect(err).NotTo(HaveOccurred())

			expectedRDNs, err := pki.UnmarshalSubjectStringToRDNSequence(literalSubject)
			Expect(err).NotTo(HaveOccurred())
			expectedDER, err := pki.MarshalRDNSequenceToRawDERBytes(expectedRDNs)
			Expect(err).NotTo(HaveOccurred())
			Expect(csr.RawSubject).To(Equal(expectedDER))

			// The order must also be preserved after the CSR is serialized to PEM and
			// parsed back (this is the form actually handed to the signer).
			key, _, err := GenerateKeyFromSpec(input.KeySpec)
			Expect(err).NotTo(HaveOccurred())
			csrPEM, err := generateCSRPEM(csr, key)
			Expect(err).NotTo(HaveOccurred())
			parsedCSR, err := extractCertificateRequest(csrPEM)
			Expect(err).NotTo(HaveOccurred())
			parsedRDNs, err := pki.UnmarshalRawDerBytesToRDNSequence(parsedCSR.RawSubject)
			Expect(err).NotTo(HaveOccurred())
			Expect(parsedRDNs).To(Equal(expectedRDNs))
		})
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

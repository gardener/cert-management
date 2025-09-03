// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package issuer_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"net/url"
	"time"

	. "github.com/gardener/gardener/pkg/utils/test/matchers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	certv1alpha1 "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	certctrl "github.com/gardener/cert-management/pkg/controller/issuer/certificate"
)

var _ = Describe("Certificate controller tests", func() {
	var (
		testRunID     string
		testNamespace *corev1.Namespace
	)

	BeforeEach(func() {
		Expect(acmeDirectoryAddress).NotTo(BeEmpty())

		ctxLocal := context.Background()

		By("Create test Namespace")
		testNamespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "certificate-",
			},
		}
		Expect(testClient.Create(ctxLocal, testNamespace)).To(Succeed())
		log.Info("Created Namespace for test", "namespaceName", testNamespace.Name)
		testRunID = testNamespace.Name

		DeferCleanup(func() {
			By("Delete test Namespace")
			Expect(testClient.Delete(ctxLocal, testNamespace)).To(Or(Succeed(), BeNotFoundError()))
		})

		By("Start manager")
		startManager(testRunID)

		DeferCleanup(func() {
			By("Stop manager")
			stopManager()
		})
	})

	Context("Self-signed certificates", func() {
		var selfSignedIssuer *certv1alpha1.Issuer

		BeforeEach(func() {
			selfSignedIssuer = &certv1alpha1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:    testNamespace.Name,
					GenerateName: "self-signed-issuer-",
				},
				Spec: certv1alpha1.IssuerSpec{
					SelfSigned: &certv1alpha1.SelfSignedSpec{},
				},
			}
			Expect(testClient.Create(ctx, selfSignedIssuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, selfSignedIssuer)).To(Succeed())
			})
			Eventually(func(g Gomega) {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(selfSignedIssuer), selfSignedIssuer)).To(Succeed())
				g.Expect(selfSignedIssuer.Status.State).To(Equal("Ready"))
			}).Should(Succeed())
		})

		It("should have appropriate not-before and not-after timestamps", func() {
			By("Create self-signed certificate")
			certificate := &certv1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:    testNamespace.Name,
					GenerateName: "self-signed-certificate-",
				},
				Spec: certv1alpha1.CertificateSpec{
					IssuerRef: &certv1alpha1.IssuerRef{
						Namespace: selfSignedIssuer.Namespace,
						Name:      selfSignedIssuer.Name,
					},
					IsCA:       ptr.To(true),
					CommonName: ptr.To("example.com"),
				},
			}
			Expect(testClient.Create(ctx, certificate)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, certificate)).To(Succeed())
			})
			Eventually(func(g Gomega) {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(certificate), certificate)).To(Succeed())
				g.Expect(certificate.Status.State).To(Equal("Ready"))
			}).WithTimeout(10 * time.Second).Should(Succeed())

			By("Read not-before and not-after timestamps")
			var (
				notBefore      = certificate.Annotations[certctrl.AnnotationNotBefore]
				notAfter       = certificate.Annotations[certctrl.AnnotationNotAfter]
				issuanceDate   = certificate.Status.IssuanceDate
				expirationDate = certificate.Status.ExpirationDate
			)
			Expect(notBefore).ToNot(BeEmpty())
			Expect(notAfter).ToNot(BeEmpty())
			Expect(issuanceDate).NotTo(BeNil())
			Expect(expirationDate).NotTo(BeNil())
			Expect(notBefore).To(Equal(*issuanceDate))
			Expect(notAfter).To(Equal(*expirationDate))

			issued, _ := time.Parse(time.RFC3339, *issuanceDate)
			expired, _ := time.Parse(time.RFC3339, *expirationDate)
			Expect(issued).To(BeTemporally("<", expired))
		})

		It("should be properly created with subject alternative names (SANs)", func() {
			By("Create self-signed certificate with SANs")
			certificate := &certv1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:    testNamespace.Name,
					GenerateName: "self-signed-certificate-with-sans-",
				},
				Spec: certv1alpha1.CertificateSpec{
					IssuerRef: &certv1alpha1.IssuerRef{
						Namespace: selfSignedIssuer.Namespace,
						Name:      selfSignedIssuer.Name,
					},
					IsCA:           ptr.To(true),
					CommonName:     ptr.To("example.com"),
					EmailAddresses: []string{"foo@example.com", "bar@example.com"},
					IPAddresses:    []string{"1.1.1.1", "1.0.0.1"},
					URIs:           []string{"ftp://ftp.example.com", "urn:isbn:9780718097914"},
				},
			}
			Expect(testClient.Create(ctx, certificate)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, certificate)).To(Succeed())
			})
			Eventually(func(g Gomega) {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(certificate), certificate)).To(Succeed())
				g.Expect(certificate.Status.State).To(Equal("Ready"))
			}).WithTimeout(10 * time.Second).Should(Succeed())

			By("Read certificate secret")
			secret := &corev1.Secret{}
			err := testClient.Get(ctx, client.ObjectKey{
				Namespace: certificate.Spec.SecretRef.Namespace,
				Name:      certificate.Spec.SecretRef.Name,
			}, secret)
			Expect(err).NotTo(HaveOccurred())

			By("Decode certificate from secret")
			certBlock, _ := pem.Decode(secret.Data[corev1.TLSCertKey])
			Expect(certBlock).NotTo(BeNil())
			parsedCert, err := x509.ParseCertificate(certBlock.Bytes)
			Expect(err).NotTo(HaveOccurred())

			By("Check SANs in the certificate")
			Expect(parsedCert.EmailAddresses).To(ConsistOf("foo@example.com", "bar@example.com"))
			Expect(parsedCert.IPAddresses).To(ConsistOf(net.ParseIP("1.1.1.1").To4(), net.ParseIP("1.0.0.1").To4()))
			Expect(parsedCert.URIs).To(ConsistOf(&url.URL{Scheme: "ftp", Host: "ftp.example.com"}, &url.URL{Scheme: "urn", Opaque: "isbn:9780718097914"}))
		})

		It("should be properly created with SANs through a certificate signing request (CSR)", func() {
			By("Create a CSR")
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())
			certificateRequest := x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "example.com",
				},
				EmailAddresses: []string{"foo@example.com", "bar@example.com"},
				IPAddresses:    []net.IP{net.ParseIP("1.1.1.1").To4(), net.ParseIP("1.0.0.1").To4()},
				URIs:           []*url.URL{{Scheme: "ftp", Host: "ftp.example.com"}, {Scheme: "urn", Opaque: "isbn:9780718097914"}},
			}
			csrDER, err := x509.CreateCertificateRequest(rand.Reader, &certificateRequest, privateKey)
			Expect(err).NotTo(HaveOccurred())
			csrPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE REQUEST",
				Bytes: csrDER,
			})

			By("Create self-signed certificate with SANs through CSR")
			certificate := &certv1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:    testNamespace.Name,
					GenerateName: "self-signed-certificate-with-sans-csr-",
				},
				Spec: certv1alpha1.CertificateSpec{
					IssuerRef: &certv1alpha1.IssuerRef{
						Namespace: selfSignedIssuer.Namespace,
						Name:      selfSignedIssuer.Name,
					},
					IsCA: ptr.To(true),
					CSR:  csrPEM,
				},
			}
			Expect(testClient.Create(ctx, certificate)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, certificate)).To(Succeed())
			})
			Eventually(func(g Gomega) {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(certificate), certificate)).To(Succeed())
				g.Expect(certificate.Status.State).To(Equal("Ready"))
			}).WithTimeout(10 * time.Second).Should(Succeed())
		})

		DescribeTable("should reject invalid SAN values",
			func(emailAddresses []string, ipAddresses []string, uris []string, expectedErrorMessage string) {
				By("Create self-signed certificate with SANs")
				certificate := &certv1alpha1.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:    testNamespace.Name,
						GenerateName: "self-signed-certificate-with-sans-",
					},
					Spec: certv1alpha1.CertificateSpec{
						IssuerRef: &certv1alpha1.IssuerRef{
							Namespace: selfSignedIssuer.Namespace,
							Name:      selfSignedIssuer.Name,
						},
						IsCA:           ptr.To(true),
						CommonName:     ptr.To("example.com"),
						EmailAddresses: emailAddresses,
						IPAddresses:    ipAddresses,
						URIs:           uris,
					},
				}
				Expect(testClient.Create(ctx, certificate)).To(Succeed())
				DeferCleanup(func() {
					Expect(testClient.Delete(ctx, certificate)).To(Succeed())
				})
				Eventually(func(g Gomega) {
					g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(certificate), certificate)).To(Succeed())
					g.Expect(certificate.Status.State).To(Equal("Error"))
					g.Expect(*certificate.Status.Message).To(ContainSubstring(expectedErrorMessage))
				}).WithTimeout(5 * time.Second).Should(Succeed())
			},
			Entry("invalid email", []string{"invalid-email"}, nil, nil, "invalid email address"),
			Entry("invalid ip", nil, []string{"invalid-ip"}, nil, "invalid IP address"),
			Entry("invalid uri", nil, nil, []string{":foo/bar"}, "invalid URI"),
		)

		Context("with renew before", func() {
			It("should have a correct renewal date planned", func() {
				certificate := &certv1alpha1.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:    testNamespace.Name,
						GenerateName: "self-signed-certificate-with-renewbefore-",
					},
					Spec: certv1alpha1.CertificateSpec{
						IssuerRef: &certv1alpha1.IssuerRef{
							Namespace: selfSignedIssuer.Namespace,
							Name:      selfSignedIssuer.Name,
						},
						IsCA:        ptr.To(true),
						CommonName:  ptr.To("example.com"),
						Duration:    &metav1.Duration{Duration: 90 * 24 * time.Hour},
						RenewBefore: &metav1.Duration{Duration: 1 * time.Hour},
					},
				}
				Expect(testClient.Create(ctx, certificate)).To(Succeed())
				DeferCleanup(func() {
					Expect(testClient.Delete(ctx, certificate)).To(Succeed())
				})
				Eventually(func(g Gomega) {
					g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(certificate), certificate)).To(Succeed())
					g.Expect(certificate.Status.State).To(Equal("Ready"))

					notAfter, err := time.Parse(time.RFC3339, certificate.Annotations[certctrl.AnnotationNotAfter])
					Expect(err).NotTo(HaveOccurred())
					renewalDate := notAfter.Add(-1 * time.Hour)
					g.Expect(certificate.Status.RenewalDate).NotTo(BeNil())
					g.Expect(*certificate.Status.RenewalDate).To(Equal(renewalDate.Format(time.RFC3339)))
				}).WithTimeout(10 * time.Second).Should(Succeed())
			})

			DescribeTable("should reject invalid renew before values",
				func(renewBefore time.Duration, expectedErrorMessage string) {
					certificate := &certv1alpha1.Certificate{
						ObjectMeta: metav1.ObjectMeta{
							Namespace:    testNamespace.Name,
							GenerateName: "self-signed-certificate-with-renewbefore-",
						},
						Spec: certv1alpha1.CertificateSpec{
							IssuerRef: &certv1alpha1.IssuerRef{
								Namespace: selfSignedIssuer.Namespace,
								Name:      selfSignedIssuer.Name,
							},
							IsCA:        ptr.To(true),
							CommonName:  ptr.To("example.com"),
							Duration:    &metav1.Duration{Duration: 90 * 24 * time.Hour},
							RenewBefore: &metav1.Duration{Duration: renewBefore},
						},
					}
					Expect(testClient.Create(ctx, certificate)).To(Succeed())
					DeferCleanup(func() {
						Expect(testClient.Delete(ctx, certificate)).To(Succeed())
					})
					Eventually(func(g Gomega) {
						g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(certificate), certificate)).To(Succeed())
						g.Expect(certificate.Status.State).To(Equal("Error"))
						g.Expect(*certificate.Status.Message).To(ContainSubstring(expectedErrorMessage))
					}).WithTimeout(10 * time.Second).Should(Succeed())
				},
				Entry("too short", -1*time.Hour, "renewBefore must be at least 5 minutes"),
				Entry("too long", 365*24*time.Hour, "renewBefore must be less than the renewal window"),
			)
		})
	})

	Context("Self-signed certificates from CA issuer", func() {
		var caIssuer *certv1alpha1.Issuer

		BeforeEach(func() {
			By("Create self-signed issuer")
			selfSignedIssuer := &certv1alpha1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:    testNamespace.Name,
					GenerateName: "self-signed-issuer-",
				},
				Spec: certv1alpha1.IssuerSpec{
					SelfSigned: &certv1alpha1.SelfSignedSpec{},
				},
			}
			Expect(testClient.Create(ctx, selfSignedIssuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, selfSignedIssuer)).To(Succeed())
			})
			Eventually(func(g Gomega) {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(selfSignedIssuer), selfSignedIssuer)).To(Succeed())
				g.Expect(selfSignedIssuer.Status.State).To(Equal("Ready"))
			}).Should(Succeed())

			By("Create self-signed root certificate")
			rootCertificate := &certv1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:    testNamespace.Name,
					GenerateName: "root-certificate-",
				},
				Spec: certv1alpha1.CertificateSpec{
					IsCA: ptr.To(true),
					IssuerRef: &certv1alpha1.IssuerRef{
						Namespace: selfSignedIssuer.Namespace,
						Name:      selfSignedIssuer.Name,
					},
					CommonName: ptr.To("example.com"),
				},
			}
			Expect(testClient.Create(ctx, rootCertificate)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, rootCertificate)).To(Succeed())
			})
			Eventually(func(g Gomega) {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(rootCertificate), rootCertificate)).To(Succeed())
				g.Expect(rootCertificate.Status.State).To(Equal("Ready"))
			}).WithTimeout(10 * time.Second).Should(Succeed())

			By("Create CA issuer based on root certificate")
			caIssuer = &certv1alpha1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:    testNamespace.Name,
					GenerateName: "ca-issuer-",
				},
				Spec: certv1alpha1.IssuerSpec{
					CA: &certv1alpha1.CASpec{
						PrivateKeySecretRef: rootCertificate.Spec.SecretRef,
					},
				},
			}
			Expect(testClient.Create(ctx, caIssuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, caIssuer)).To(Succeed())
			})
			Eventually(func(g Gomega) {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(caIssuer), caIssuer)).To(Succeed())
				g.Expect(caIssuer.Status.State).To(Equal("Ready"))
			}).Should(Succeed())
		})

		DescribeTable("Create self-signed certificates using CA issuer",
			func(privateKeyAlgorithm certv1alpha1.PrivateKeyAlgorithm, privateKeySize int) {
				By("Create certificate using CA issuer")
				certificate := &certv1alpha1.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:    testNamespace.Name,
						GenerateName: "certificate-",
					},
					Spec: certv1alpha1.CertificateSpec{
						IssuerRef: &certv1alpha1.IssuerRef{
							Namespace: caIssuer.Namespace,
							Name:      caIssuer.Name,
						},
						PrivateKey: &certv1alpha1.CertificatePrivateKey{
							Algorithm: ptr.To(privateKeyAlgorithm),
							Size:      ptr.To(certv1alpha1.PrivateKeySize(privateKeySize)),
						},
						Duration: &metav1.Duration{
							Duration: 48 * time.Hour,
						},
						CommonName: ptr.To("example.com"),
					},
				}
				Expect(testClient.Create(ctx, certificate)).To(Succeed())
				DeferCleanup(func() {
					Expect(testClient.Delete(ctx, certificate)).To(Succeed())
				})
				Eventually(func(g Gomega) {
					g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(certificate), certificate)).To(Succeed())
					g.Expect(certificate.Status.State).To(Equal("Ready"))
				}).WithTimeout(10 * time.Second).Should(Succeed())

				By("Read certificate secret")
				secret := &corev1.Secret{}
				Expect(testClient.Get(ctx, client.ObjectKey{
					Namespace: certificate.Spec.SecretRef.Namespace,
					Name:      certificate.Spec.SecretRef.Name,
				}, secret)).To(Succeed())

				By("Check that the certificate secret private key uses the expected algorithm and size")
				privateKeyBlock, _ := pem.Decode(secret.Data[corev1.TLSPrivateKeyKey]) // tls.key
				switch privateKeyAlgorithm {
				case certv1alpha1.ECDSAKeyAlgorithm:
					privateKey, err := x509.ParseECPrivateKey(privateKeyBlock.Bytes)
					Expect(err).NotTo(HaveOccurred())
					Expect(privateKey).NotTo(BeNil())
					Expect(privateKey.Curve.Params().BitSize).To(Equal(privateKeySize))
				case certv1alpha1.RSAKeyAlgorithm:
					privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
					Expect(err).NotTo(HaveOccurred())
					Expect(privateKey).NotTo(BeNil())
					Expect(privateKey.N.BitLen()).To(Equal(privateKeySize))
				default:
					Fail("Unsupported private key algorithm")
				}
			},
			Entry("ECDSA 256", certv1alpha1.ECDSAKeyAlgorithm, 256),
			Entry("ECDSA 384", certv1alpha1.ECDSAKeyAlgorithm, 384),
			Entry("RSA 2048", certv1alpha1.RSAKeyAlgorithm, 2048),
			Entry("RSA 3072", certv1alpha1.RSAKeyAlgorithm, 3072),
			Entry("RSA 4096", certv1alpha1.RSAKeyAlgorithm, 4096),
		)

		It("should be properly created with subject alternative names (SANs)", func() {
			By("Create certificate from CA with SANs")
			certificate := &certv1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:    testNamespace.Name,
					GenerateName: "ca-certificate-with-sans-",
				},
				Spec: certv1alpha1.CertificateSpec{
					IssuerRef: &certv1alpha1.IssuerRef{
						Namespace: caIssuer.Namespace,
						Name:      caIssuer.Name,
					},
					CommonName: ptr.To("example.com"),
					Duration: &metav1.Duration{
						Duration: 48 * time.Hour,
					},
					EmailAddresses: []string{"foo@example.com", "bar@example.com"},
					IPAddresses:    []string{"1.1.1.1", "1.0.0.1"},
					URIs:           []string{"ftp://ftp.example.com", "urn:isbn:9780718097914"},
				},
			}
			Expect(testClient.Create(ctx, certificate)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, certificate)).To(Succeed())
			})
			Eventually(func(g Gomega) {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(certificate), certificate)).To(Succeed())
				g.Expect(certificate.Status.State).To(Equal("Ready"))
			}).WithTimeout(10 * time.Second).Should(Succeed())

			By("Read certificate secret")
			secret := &corev1.Secret{}
			err := testClient.Get(ctx, client.ObjectKey{
				Namespace: certificate.Spec.SecretRef.Namespace,
				Name:      certificate.Spec.SecretRef.Name,
			}, secret)
			Expect(err).NotTo(HaveOccurred())

			By("Decode certificate from secret")
			certBlock, _ := pem.Decode(secret.Data[corev1.TLSCertKey])
			Expect(certBlock).NotTo(BeNil())
			parsedCert, err := x509.ParseCertificate(certBlock.Bytes)
			Expect(err).NotTo(HaveOccurred())

			By("Check SANs in the certificate")
			Expect(parsedCert.EmailAddresses).To(ConsistOf("foo@example.com", "bar@example.com"))
			Expect(parsedCert.IPAddresses).To(ConsistOf(net.ParseIP("1.1.1.1").To4(), net.ParseIP("1.0.0.1").To4()))
			Expect(parsedCert.URIs).To(ConsistOf(&url.URL{Scheme: "ftp", Host: "ftp.example.com"}, &url.URL{Scheme: "urn", Opaque: "isbn:9780718097914"}))
		})

		It("should be properly created with SANs through a certificate signing request (CSR)", func() {
			By("Create a CSR")
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())
			certificateRequest := x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "example.com",
				},
				EmailAddresses: []string{"foo@example.com", "bar@example.com"},
				IPAddresses:    []net.IP{net.ParseIP("1.1.1.1").To4(), net.ParseIP("1.0.0.1").To4()},
				URIs:           []*url.URL{{Scheme: "ftp", Host: "ftp.example.com"}, {Scheme: "urn", Opaque: "isbn:9780718097914"}},
			}
			csrDER, err := x509.CreateCertificateRequest(rand.Reader, &certificateRequest, privateKey)
			Expect(err).NotTo(HaveOccurred())
			csrPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE REQUEST",
				Bytes: csrDER,
			})

			By("Create certificate from CA with SANs through CSR")
			certificate := &certv1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:    testNamespace.Name,
					GenerateName: "ca-certificate-with-sans-csr-",
				},
				Spec: certv1alpha1.CertificateSpec{
					IssuerRef: &certv1alpha1.IssuerRef{
						Namespace: caIssuer.Namespace,
						Name:      caIssuer.Name,
					},
					Duration: &metav1.Duration{
						Duration: 48 * time.Hour,
					},
					CSR: csrPEM,
				},
			}
			Expect(testClient.Create(ctx, certificate)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, certificate)).To(Succeed())
			})
			Eventually(func(g Gomega) {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(certificate), certificate)).To(Succeed())
				g.Expect(certificate.Status.State).To(Equal("Ready"))
			}).WithTimeout(10 * time.Second).Should(Succeed())
		})
	})
})

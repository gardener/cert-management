/*
 * // SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
 * //
 * // SPDX-License-Identifier: Apache-2.0
 */

package issuer_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/gardener/controller-manager-library/pkg/ctxutil"
	. "github.com/gardener/gardener/pkg/utils/test/matchers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/shared/legobridge"
)

var _ = Describe("Issuer controller tests", func() {
	var (
		testRunID     string
		testNamespace *corev1.Namespace

		checkIssuerStateReady = func(issuer *v1alpha1.Issuer) {
			GinkgoHelper()
			Eventually(func(g Gomega) string {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(issuer), issuer)).To(Succeed())
				g.Expect(issuer.Status.ObservedGeneration).To(Equal(issuer.Generation))
				return issuer.Status.State
			}).Should(Equal("Ready"))
		}

		checkCertificateStateReady = func(cert *v1alpha1.Certificate) {
			GinkgoHelper()
			Eventually(func(g Gomega) string {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(cert), cert)).To(Succeed())
				g.Expect(cert.Status.ObservedGeneration).To(Equal(cert.Generation))
				return cert.Status.State
			}).Should(Equal("Ready"))
		}
	)

	BeforeEach(func() {
		Expect(acmeDirectoryAddress).NotTo(BeEmpty())

		ctxLocal := context.Background()

		By("Create test Namespace")
		testNamespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "issuer-",
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

	Context("ACME issuer", func() {
		It("should create an ACME issuer", func() {
			issuer := getAcmeIssuer(testRunID)
			Expect(testClient.Create(ctx, issuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, issuer)).To(Succeed())
			})

			checkIssuerStateReady(issuer)
		})

		It("should create a certificate", func() {
			By("Create ACME issuer")
			issuer := getAcmeIssuer(testRunID)
			Expect(testClient.Create(ctx, issuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, issuer)).To(Succeed())
			})

			checkIssuerStateReady(issuer)

			By("Create certificate")
			cert := getCertificate(testRunID, "acme-certificate", "example.com", issuer.Namespace, issuer.Name)
			Expect(testClient.Create(ctx, cert)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, cert)).To(Succeed())
			})

			By("Wait for certificate to become ready")
			checkCertificateStateReady(cert)
		})

		It("should reconcile an orphan pending certificate with an ACME issuer", func() {
			By("Create ACME issuer")
			issuer := getAcmeIssuer(testRunID)
			Expect(testClient.Create(ctx, issuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, issuer)).To(Succeed())
			})

			checkIssuerStateReady(issuer)

			By("Stop manager")
			stopManager()

			By("Create orphan pending certificate")
			cert := getCertificate(testRunID, "orphan-pending-certificate", "example.com", issuer.Namespace, issuer.Name)
			ctxLocal := context.Background()
			Expect(testClient.Create(ctxLocal, cert)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctxLocal, cert)).To(Succeed())
			})
			cert.Status = v1alpha1.CertificateStatus{
				ObservedGeneration:   cert.Generation,
				State:                "Pending",
				Message:              ptr.To("simulated orphan pending certificate"),
				LastPendingTimestamp: ptr.To(metav1.Now()),
				BackOff: &v1alpha1.BackOffState{
					ObservedGeneration: cert.Generation,
					RetryAfter:         metav1.Time{Time: time.Now().Add(1 * time.Second)},
					RetryInterval:      metav1.Duration{Duration: 120 * time.Second},
				},
			}
			Expect(testClient.SubResource("status").Update(ctxLocal, cert)).To(Succeed())

			By("Start manager")
			startManager(testRunID)

			By("Wait for certificate to become ready")
			Eventually(func(g Gomega) string {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(cert), cert)).To(Succeed())
				return cert.Status.State
			}).WithPolling(500 * time.Millisecond).WithTimeout(40 * time.Second).Should(Equal("Ready"))
		})

		It("should reconcile a certificate referencing unallowed target issuer", func() {
			cert := getCertificate(testRunID, "certificate-with-unallowed-issuer", "example.com", "namespace1", "foo")
			Expect(testClient.Create(ctx, cert)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, cert)).To(Succeed())
			})

			By("Wait for certificate to become ready")
			Eventually(func(g Gomega) v1alpha1.CertificateStatus {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(cert), cert)).To(Succeed())
				return cert.Status
			}).Should(MatchFields(IgnoreExtras, Fields{
				"State":   Equal("Error"),
				"Message": PointTo(Equal("target issuers not allowed")),
			}))
		})

		It("should not be able to create certificate if no quota is left", func() {
			By("Create ACME issuer")
			issuer := getAcmeIssuer(testRunID)
			issuer.Spec.RequestsPerDayQuota = ptr.To(1)
			Expect(testClient.Create(ctx, issuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, issuer)).To(Succeed())
			})

			checkIssuerStateReady(issuer)
			Expect(issuer.Spec.RequestsPerDayQuota).To(PointTo(Equal(1)))

			By("Create first certificate")
			cert1 := getCertificate(testRunID, "acme-certificate1", "example.com", issuer.Namespace, issuer.Name)
			Expect(testClient.Create(ctx, cert1)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, cert1)).To(Succeed())
			})

			By("Wait for first certificate to become ready")
			checkCertificateStateReady(cert1)

			By("Create second certificate")
			cert2 := getCertificate(testRunID, "acme-certificate2", "other.domain.com", issuer.Namespace, issuer.Name)
			Expect(testClient.Create(ctx, cert2)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, cert2)).To(Succeed())
			})

			By("Wait for second certificate to fail")
			Eventually(func(g Gomega) v1alpha1.CertificateStatus {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(cert2), cert2)).To(Succeed())
				return cert2.Status
			}).Should(MatchFields(IgnoreExtras, Fields{
				"State":   Equal("Error"),
				"Message": PointTo(ContainSubstring("request quota exhausted.")),
			}))
		})

		It("should reuse certificate and not consume quota if multiple certificates are created for the same domain", func() {
			By("Create ACME issuer")
			issuer := getAcmeIssuer(testRunID)
			issuer.Spec.RequestsPerDayQuota = ptr.To(1)
			Expect(testClient.Create(ctx, issuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, issuer)).To(Succeed())
			})

			checkIssuerStateReady(issuer)
			Expect(issuer.Spec.RequestsPerDayQuota).To(PointTo(Equal(1)))

			By("Create first certificate")
			cert1 := getCertificate(testRunID, "acme-certificate1", "example.com", issuer.Namespace, issuer.Name)
			Expect(testClient.Create(ctx, cert1)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, cert1)).To(Succeed())
			})

			By("Wait for first certificate to become ready")
			checkCertificateStateReady(cert1)

			By("Create second certificate")
			cert2 := getCertificate(testRunID, "acme-certificate2", "example.com", issuer.Namespace, issuer.Name)
			Expect(testClient.Create(ctx, cert2)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, cert2)).To(Succeed())
			})

			By("Wait for second certificate to become ready")
			Eventually(func(g Gomega) v1alpha1.CertificateStatus {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(cert2), cert2)).To(Succeed())
				return cert2.Status
			}).Should(MatchFields(IgnoreExtras, Fields{
				"State": Equal("Ready"),
				// The message of a provisioned certificate looks like this:
				// certificate (SN 45:11:fb:59:68:54:49:d4:c3:ab:26:f1:35:09:3c:29:f4:7) valid from 2025-01-29 15:46:32 +0000 UTC to 2025-04-29 15:46:31 +0000 UTC
				// As it contains the serial number (SN) we can assert that the SN is the same between both certificate resources.
				"Message": Equal(cert1.Status.Message),
			}))
		})

		It("should renew a certificate", func() {
			By("Create ACME issuer")
			issuer := getAcmeIssuer(testRunID)
			Expect(testClient.Create(ctx, issuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, issuer)).To(Succeed())
			})

			By("Wait for issuer to become ready")
			checkIssuerStateReady(issuer)

			By("Create certificate")
			cert := getCertificate(testRunID, "acme-certificate1", "example.com", issuer.Namespace, issuer.Name)
			Expect(testClient.Create(ctx, cert)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, cert)).To(Succeed())
			})

			By("Wait for certificate to become ready")
			checkCertificateStateReady(cert)

			By("Trigger renewal")
			oldExpirationDate := &cert.Status.ExpirationDate
			Eventually(func(g Gomega) {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(cert), cert)).To(Succeed())
				cert.Spec.Renew = ptr.To(true)
				g.Expect(testClient.Update(ctx, cert)).To(Succeed())
			}).WithPolling(10 * time.Millisecond).Should(Succeed())

			By("Wait for renewal")
			checkCertificateStateReady(cert)
			Expect(cert.Status.ExpirationDate).ToNot(PointTo(Equal(oldExpirationDate)))
		})

		It("should have validation errors for issuer secret with invalid secret", func() {
			By("Create ACME issuer")
			issuer := getAcmeIssuer(testRunID)
			issuer.Spec.ACME.PrivateKeySecretRef = &corev1.SecretReference{
				Name:      "invalid-secret",
				Namespace: testRunID,
			}
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      issuer.Spec.ACME.PrivateKeySecretRef.Name,
					Namespace: testRunID,
				},
				Data: map[string][]byte{
					legobridge.KeyPrivateKey: []byte("dummy"),
				},
			}
			Expect(testClient.Create(ctx, secret)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, secret)).To(Succeed())
			})
			Expect(testClient.Create(ctx, issuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, issuer)).To(Succeed())
			})

			By("Wait for issuer to have state error because of invalid private key encoding")
			Eventually(func(g Gomega) v1alpha1.IssuerStatus {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(issuer), issuer)).To(Succeed())
				return issuer.Status
			}).Should(MatchFields(IgnoreExtras, Fields{
				"State":   Equal("Error"),
				"Message": PointTo(Equal(fmt.Sprintf("validation of data keys failed for secret %s: value for key `privateKey` is invalid: decoding pem block for private key failed", client.ObjectKeyFromObject(secret)))),
			}))

			By("Wait for issuer to auto-registrate")
			Expect(testClient.Delete(ctx, secret)).To(Succeed())
			Eventually(func(g Gomega) string {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(issuer), issuer)).To(Succeed())
				return issuer.Status.State
			}).Should(Equal("Ready"))

			By("Wait for issuer to have validation error because of invalid key")
			Expect(testClient.Get(ctx, client.ObjectKeyFromObject(secret), secret)).To(Succeed())
			secret.Data["invalid-key"] = []byte("this-is-not-a-data-key")
			secret.Data[legobridge.ObsoleteKeyEmail] = []byte("dummy@example.com") // This key is obsolete but still allowed for backward compatibility
			Expect(testClient.Update(ctx, secret)).To(Succeed())
			Eventually(func(g Gomega) v1alpha1.IssuerStatus {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(issuer), issuer)).To(Succeed())
				return issuer.Status
			}).Should(MatchFields(IgnoreExtras, Fields{
				"State":   Equal("Error"),
				"Message": PointTo(Equal(fmt.Sprintf("validation of data keys failed for secret %s: invalid secret data keys: `invalid-key`", client.ObjectKeyFromObject(secret)))),
			}))
		})

		It("should have validation errors for issuer secret with invalid EAB secret", func() {
			By("Create ACME issuer")
			issuer := getAcmeIssuer(testRunID)
			issuer.Spec.ACME.ExternalAccountBinding = &v1alpha1.ACMEExternalAccountBinding{
				KeyID: "test",
				KeySecretRef: &corev1.SecretReference{
					Name:      "invalid-secret",
					Namespace: testRunID,
				},
			}
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      issuer.Spec.ACME.ExternalAccountBinding.KeySecretRef.Name,
					Namespace: issuer.Spec.ACME.ExternalAccountBinding.KeySecretRef.Namespace,
				},
				Data: map[string][]byte{
					legobridge.KeyHmacKey: []byte("dummy"),
					"invalid-key":         []byte("this-is-not-a-data-key"),
				},
			}
			Expect(testClient.Create(ctx, secret)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, secret)).To(Succeed())
			})
			Expect(testClient.Create(ctx, issuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, issuer)).To(Succeed())
			})

			By("Wait for issuer to have state error because of invalid data key")
			Eventually(func(g Gomega) v1alpha1.IssuerStatus {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(issuer), issuer)).To(Succeed())
				return issuer.Status
			}).Should(MatchFields(IgnoreExtras, Fields{
				"State":   Equal("Error"),
				"Message": PointTo(Equal(fmt.Sprintf("loading EAB secret failed: EAB secret %s contains unexpected keys: invalid-key", client.ObjectKeyFromObject(secret)))),
			}))

			By("Wait for issuer to have state error because of invalid key value (not base64 encoded)")
			Expect(testClient.Get(ctx, client.ObjectKeyFromObject(secret), secret)).To(Succeed())
			delete(secret.Data, "invalid-key")
			Expect(testClient.Update(ctx, secret)).To(Succeed())
			Eventually(func(g Gomega) v1alpha1.IssuerStatus {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(issuer), issuer)).To(Succeed())
				return issuer.Status
			}).Should(MatchFields(IgnoreExtras, Fields{
				"State":   Equal("Error"),
				"Message": PointTo(HavePrefix("creating registration user failed: acme: could not decode hmac key: illegal base64 data")),
			}))

			By("Wait for issuer to have state error because of key value too short")
			Expect(testClient.Get(ctx, client.ObjectKeyFromObject(secret), secret)).To(Succeed())
			secret.Data[legobridge.KeyHmacKey] = []byte(base64.RawURLEncoding.EncodeToString([]byte("dummy")))
			Expect(testClient.Update(ctx, secret)).To(Succeed())
			Eventually(func(g Gomega) v1alpha1.IssuerStatus {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(issuer), issuer)).To(Succeed())
				return issuer.Status
			}).Should(MatchFields(IgnoreExtras, Fields{
				"State":   Equal("Error"),
				"Message": PointTo(HavePrefix("creating registration user failed: acme: error signing eab content: failed to External Account Binding sign content: go-jose/go-jose: invalid key size for algorithm")),
			}))
		})
	})

	Context("Self-signed issuer", func() {
		var issuer *v1alpha1.Issuer
		BeforeEach(func() {
			issuer = &v1alpha1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testRunID,
					Name:      "self-signed-issuer",
				},
				Spec: v1alpha1.IssuerSpec{
					SelfSigned: &v1alpha1.SelfSignedSpec{},
				},
			}

			Expect(testClient.Create(ctx, issuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, issuer)).To(Succeed())
			})

			checkIssuerStateReady(issuer)
		})

		It("should be able to create self-signed certificates", func() {
			By("Create self-signed certificate")
			certificate := getCertificate(testRunID, "self-signed-certificate", "ca1.mydomain.com", issuer.Namespace, issuer.Name)
			certificate.Spec.IsCA = ptr.To(true)
			Expect(testClient.Create(ctx, certificate)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, certificate)).To(Succeed())
			})

			checkCertificateStateReady(certificate)

			By("Resolve certificate secret reference")
			secretReference := certificate.Spec.SecretRef
			secretKey := client.ObjectKey{Name: secretReference.Name, Namespace: secretReference.Namespace}
			secret := &corev1.Secret{}
			Expect(testClient.Get(ctx, secretKey, secret)).To(Succeed())
			Expect(secret.Data).To(HaveKeyWithValue("ca.crt", Not(BeEmpty())))
			Expect(secret.Data).To(HaveKeyWithValue("tls.crt", Not(BeEmpty())))
			Expect(secret.Data).To(HaveKeyWithValue("tls.key", Not(BeEmpty())))
		})

		It("should not be able to create self-signed certificate if the duration is < 48h", func() {
			By("Create self-signed certificate")
			certificate := getCertificate(testRunID, "self-signed-certificate", "ca1.mydomain.com", issuer.Namespace, issuer.Name)
			certificate.Spec.IsCA = ptr.To(true)
			certificate.Spec.Duration = &metav1.Duration{Duration: 1 * time.Hour}
			Expect(testClient.Create(ctx, certificate)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, certificate)).To(Succeed())
			})

			Eventually(func(g Gomega) v1alpha1.CertificateStatus {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(certificate), certificate)).To(Succeed())
				return certificate.Status
			}).Should(MatchFields(IgnoreExtras, Fields{
				"State":   Equal("Error"),
				"Message": PointTo(ContainSubstring("certificate duration must be at least 48h0m0s")),
			}))
		})

		It("should not be able to create self-signed certificate if IsCA = false", func() {
			By("Create self-signed certificate")
			certificate := getCertificate(testRunID, "self-signed-certificate", "ca1.mydomain.com", issuer.Namespace, issuer.Name)
			certificate.Spec.IsCA = ptr.To(false)
			Expect(testClient.Create(ctx, certificate)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, certificate)).To(Succeed())
			})

			Eventually(func(g Gomega) v1alpha1.CertificateStatus {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(certificate), certificate)).To(Succeed())
				return certificate.Status
			}).Should(MatchFields(IgnoreExtras, Fields{
				"State":   Equal("Error"),
				"Message": PointTo(ContainSubstring("self signed certificates must set 'spec.isCA: true'")),
			}))
		})
	})

	Context("Certificate Authority issuer", func() {
		It("should be able to create CA issuer", func() {
			By("Get Certificate")
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())
			keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
			data, err := createPemCertificate(privateKey, privateKey.Public(), "RSA PRIVATE KEY", keyBytes)
			Expect(err).NotTo(HaveOccurred())

			By("Create Secret")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "issuer-ca-secret",
					Namespace: testRunID,
				},
				Data: data,
				Type: corev1.SecretTypeTLS,
			}
			Expect(testClient.Create(ctx, secret)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, secret)).To(Succeed())
			})

			By("Create CA Issuer")
			issuer := &v1alpha1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testRunID,
					Name:      "issuer-ca",
				},
				Spec: v1alpha1.IssuerSpec{
					CA: &v1alpha1.CASpec{
						PrivateKeySecretRef: &corev1.SecretReference{
							Name:      secret.Name,
							Namespace: secret.Namespace,
						},
					},
				},
			}
			Expect(testClient.Create(ctx, issuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, issuer)).To(Succeed())
			})

			checkIssuerStateReady(issuer)
		})
	})

	Context("Chained Certificate Authority issuer", func() {
		It("should be able to create CA issuer", func() {
			By("Create self-signed CA issuer")
			selfSignedIssuer := &v1alpha1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testRunID,
					Name:      "self-signed-issuer",
				},
				Spec: v1alpha1.IssuerSpec{
					SelfSigned: &v1alpha1.SelfSignedSpec{},
				},
			}
			Expect(testClient.Create(ctx, selfSignedIssuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, selfSignedIssuer)).To(Succeed())
			})
			checkIssuerStateReady(selfSignedIssuer)

			By("Create root CA certificate")
			rootCACertificate := getCertificate(testRunID, "root-ca-certificate", "root-ca.mydomain.com", testRunID, selfSignedIssuer.Name)
			rootCACertificate.Spec.SecretRef = &corev1.SecretReference{
				Name:      "root-ca-certificate-secret",
				Namespace: testRunID,
			}
			rootCACertificate.Spec.IsCA = ptr.To(true)
			rootCACertificate.Spec.Duration = &metav1.Duration{Duration: 3 * 365 * 24 * time.Hour} // 3 years
			Expect(testClient.Create(ctx, rootCACertificate)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, rootCACertificate)).To(Succeed())
			})
			checkCertificateStateReady(rootCACertificate)

			By("Create issuer with root CA certificate")
			caRootIssuer := &v1alpha1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testRunID,
					Name:      "ca-root-issuer",
				},
				Spec: v1alpha1.IssuerSpec{
					CA: &v1alpha1.CASpec{
						PrivateKeySecretRef: rootCACertificate.Spec.SecretRef,
					},
				},
			}
			Expect(testClient.Create(ctx, caRootIssuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, caRootIssuer)).To(Succeed())
			})
			checkIssuerStateReady(caRootIssuer)

			By("Create intermediate CA certificate")
			intermediateCACertificate := getCertificate(testRunID, "intermediate-ca-certificate", "intermediate-ca.root-ca.mydomain.com", testRunID, caRootIssuer.Name)
			intermediateCACertificate.Spec.SecretRef = &corev1.SecretReference{
				Name:      "intermediate-ca-certificate-secret",
				Namespace: testRunID,
			}
			intermediateCACertificate.Spec.IsCA = ptr.To(true)
			intermediateCACertificate.Spec.Duration = &metav1.Duration{Duration: 1 * 365 * 24 * time.Hour} // 1 year
			Expect(testClient.Create(ctx, intermediateCACertificate)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, intermediateCACertificate)).To(Succeed())
			})
			checkCertificateStateReady(intermediateCACertificate)

			By("Create issuer with intermediate CA certificate")
			caIntermediateIssuer := &v1alpha1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testRunID,
					Name:      "ca-intermediate-issuer",
				},
				Spec: v1alpha1.IssuerSpec{
					CA: &v1alpha1.CASpec{
						PrivateKeySecretRef: intermediateCACertificate.Spec.SecretRef,
					},
				},
			}
			Expect(testClient.Create(ctx, caIntermediateIssuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, caIntermediateIssuer)).To(Succeed())
			})
			checkIssuerStateReady(caIntermediateIssuer)

			By("Create certificate")
			fooCertificate := getCertificate(testRunID, "foo-certificate", "foo.intermediate-ca.root-ca.mydomain.com", testRunID, caIntermediateIssuer.Name)
			fooCertificate.Spec.SecretRef = &corev1.SecretReference{
				Name:      "foo-certificate-secret",
				Namespace: testRunID,
			}
			Expect(testClient.Create(ctx, fooCertificate)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, fooCertificate)).To(Succeed())
			})
			checkCertificateStateReady(fooCertificate)

			secret := &corev1.Secret{}
			By("Verify certificate secret contains certificate chain to first CA")
			secretKey := client.ObjectKey{Name: fooCertificate.Spec.SecretRef.Name, Namespace: fooCertificate.Spec.SecretRef.Namespace}
			Expect(testClient.Get(ctx, secretKey, secret)).To(Succeed())
			certData := secret.Data[corev1.TLSCertKey]
			block, rest := pem.Decode(certData)
			Expect(block).NotTo(BeNil())
			Expect(block.Type).To(Equal("CERTIFICATE"))
			cert1, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			block, rest = pem.Decode(rest)
			Expect(block).NotTo(BeNil())
			Expect(block.Type).To(Equal("CERTIFICATE"))
			cert2, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(rest).To(BeEmpty())
			Expect(cert1.Issuer.CommonName).To(Equal("intermediate-ca.root-ca.mydomain.com"))
			Expect(cert2.Issuer.CommonName).To(Equal("root-ca.mydomain.com"))
		})
	})
})

func getAcmeIssuer(namespace string) *v1alpha1.Issuer {
	return &v1alpha1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:    namespace,
			GenerateName: "acme-",
		},
		Spec: v1alpha1.IssuerSpec{
			ACME: &v1alpha1.ACMESpec{
				Email:                      "foo@somewhere-foo-123456.com",
				Server:                     acmeDirectoryAddress,
				AutoRegistration:           true,
				SkipDNSChallengeValidation: ptr.To(true),
			},
		},
	}
}

func getCertificate(certificateNamespace, certificateName, commonName, issuerNamespace, issuerName string) *v1alpha1.Certificate {
	return &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:    certificateNamespace,
			GenerateName: fmt.Sprintf("%v-", certificateName),
		},
		Spec: v1alpha1.CertificateSpec{
			CommonName: ptr.To(commonName),
			IssuerRef: &v1alpha1.IssuerRef{
				Namespace: issuerNamespace,
				Name:      issuerName,
			},
		},
	}
}

func createPemCertificate(privateKey crypto.PrivateKey, pubKey crypto.PublicKey, header string, privateKeyBytes []byte) (map[string][]byte, error) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1234),
		Subject:               pkix.Name{CommonName: "example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privateKey)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: header, Bytes: privateKeyBytes})
	return map[string][]byte{
		corev1.TLSCertKey:       certPEM,
		corev1.TLSPrivateKeyKey: keyPEM,
	}, nil
}

func startManager(testRunID string) {
	newContext()
	go func() {
		defer GinkgoRecover()
		args := []string{
			"--kubeconfig", kubeconfigFile,
			"--controllers", "issuer",
			"--issuer-namespace", testRunID,
			"--omit-lease",
			"--pool.size", "1",
			"--issuer.renewal-window", "24h",
		}
		runControllerManager(ctx, args)
	}()
}

func stopManager() {
	if ctx != nil {
		ctxutil.Cancel(ctx)
	}
}

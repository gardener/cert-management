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
	"encoding/pem"
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
)

var _ = Describe("Issuer controller tests", func() {
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
			issuer := getAcmeIssuer(testRunID, false)
			Expect(testClient.Create(ctx, issuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, issuer)).To(Succeed())
			})

			Eventually(func(g Gomega) {
				Expect(testClient.Get(ctx, client.ObjectKeyFromObject(issuer), issuer)).To(Succeed())
				g.Expect(issuer.Status.State).To(Equal("Ready"))
			}).Should(Succeed())
		})

		It("should create a certificate", func() {
			By("Create ACME issuer")
			issuer := getAcmeIssuer(testRunID, true)
			Expect(testClient.Create(ctx, issuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, issuer)).To(Succeed())
			})

			Eventually(func(g Gomega) {
				Expect(testClient.Get(ctx, client.ObjectKeyFromObject(issuer), issuer)).To(Succeed())
				g.Expect(issuer.Status.State).To(Equal("Ready"))
			}).Should(Succeed())

			By("Create certificate")
			cert := getCertificate(testRunID, "acme-certificate", "example.com", issuer.Namespace, issuer.Name)
			Expect(testClient.Create(ctx, cert)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, cert)).To(Succeed())
			})

			By("Wait for certificate to become ready")
			Eventually(func(g Gomega) string {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(cert), cert)).To(Succeed())
				return cert.Status.State
			}).Should(Equal("Ready"))
		})

		It("should reconcile an orphan pending certificate with an ACME issuer", func() {
			By("Create ACME issuer")
			issuer := getAcmeIssuer(testRunID, true)
			Expect(testClient.Create(ctx, issuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, issuer)).To(Succeed())
			})

			Eventually(func(g Gomega) {
				Expect(testClient.Get(ctx, client.ObjectKeyFromObject(issuer), issuer)).To(Succeed())
				g.Expect(issuer.Status.State).To(Equal("Ready"))
			}).Should(Succeed())

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
			issuer := getAcmeIssuer(testRunID, true)
			issuer.Spec.RequestsPerDayQuota = ptr.To(1)
			Expect(testClient.Create(ctx, issuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, issuer)).To(Succeed())
			})

			Eventually(func(g Gomega) {
				Expect(testClient.Get(ctx, client.ObjectKeyFromObject(issuer), issuer)).To(Succeed())
				g.Expect(issuer.Status.State).To(Equal("Ready"))
				g.Expect(issuer.Status.RequestsPerDayQuota).To(Equal(1))
			}).Should(Succeed())

			By("Create first certificate")
			cert1 := getCertificate(testRunID, "acme-certificate1", "example.com", issuer.Namespace, issuer.Name)
			Expect(testClient.Create(ctx, cert1)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, cert1)).To(Succeed())
			})

			By("Wait for first certificate to become ready")
			Eventually(func(g Gomega) string {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(cert1), cert1)).To(Succeed())
				return cert1.Status.State
			}).Should(Equal("Ready"))

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

		It("should reuse certificate if multiple certificates are created for the same domain", func() {
			By("Create ACME issuer")
			issuer := getAcmeIssuer(testRunID, true)
			issuer.Spec.RequestsPerDayQuota = ptr.To(1)
			Expect(testClient.Create(ctx, issuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, issuer)).To(Succeed())
			})

			Eventually(func(g Gomega) {
				Expect(testClient.Get(ctx, client.ObjectKeyFromObject(issuer), issuer)).To(Succeed())
				g.Expect(issuer.Status.State).To(Equal("Ready"))
				g.Expect(issuer.Status.RequestsPerDayQuota).To(Equal(1))
			}).Should(Succeed())

			By("Create first certificate")
			cert1 := getCertificate(testRunID, "acme-certificate1", "example.com", issuer.Namespace, issuer.Name)
			Expect(testClient.Create(ctx, cert1)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, cert1)).To(Succeed())
			})

			By("Wait for first certificate to become ready")
			Eventually(func(g Gomega) string {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(cert1), cert1)).To(Succeed())
				return cert1.Status.State
			}).Should(Equal("Ready"))

			By("Create second certificate")
			cert2 := getCertificate(testRunID, "acme-certificate2", "example.com", issuer.Namespace, issuer.Name)
			Expect(testClient.Create(ctx, cert2)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, cert2)).To(Succeed())
			})

			By("Wait for second certificate to become ready")
			Eventually(func(g Gomega) string {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(cert2), cert2)).To(Succeed())
				return cert2.Status.State
			}).Should(Equal("Ready"))
		})

		It("should renew a certificate", func() {
			By("Create ACME issuer")
			issuer := getAcmeIssuer(testRunID, true)
			Expect(testClient.Create(ctx, issuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, issuer)).To(Succeed())
			})

			By("Wait for issuer to become ready")
			Eventually(func(g Gomega) {
				Expect(testClient.Get(ctx, client.ObjectKeyFromObject(issuer), issuer)).To(Succeed())
				g.Expect(issuer.Status.State).To(Equal("Ready"))
			}).Should(Succeed())

			By("Create certificate")
			cert := getCertificate(testRunID, "acme-certificate1", "example.com", issuer.Namespace, issuer.Name)
			cert.Spec.Renew = ptr.To(false)
			Expect(testClient.Create(ctx, cert)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, cert)).To(Succeed())
			})

			By("Wait for certificate to become ready")
			Eventually(func(g Gomega) string {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(cert), cert)).To(Succeed())
				return cert.Status.State
			}).Should(Equal("Ready"))

			By("Trigger renewal")
			oldExpirationDate := cert.Status.ExpirationDate
			Eventually(func(g Gomega) {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(cert), cert)).To(Succeed())
				cert.Spec.Renew = ptr.To(true)
				g.Expect(testClient.Update(ctx, cert)).To(Succeed())
			}).Should(Succeed())

			By("Wait for renewal")
			Eventually(func(g Gomega) v1alpha1.CertificateStatus {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(cert), cert)).To(Succeed())
				return cert.Status
			}).Should(MatchFields(IgnoreExtras, Fields{
				"State":          Equal("Ready"),
				"ExpirationDate": Not(Equal(oldExpirationDate)),
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

			Eventually(func(g Gomega) {
				Expect(testClient.Get(ctx, client.ObjectKeyFromObject(issuer), issuer)).To(Succeed())
				g.Expect(issuer.Status.State).To(Equal("Ready"))
			}).Should(Succeed())
		})

		It("should be able to create self-signed certificates", func() {
			By("Create self-signed certificate")
			certificate := getCertificate(testRunID, "self-signed-certificate", "ca1.mydomain.com", issuer.Namespace, issuer.Name)
			certificate.Spec.IsCA = ptr.To(true)
			Expect(testClient.Create(ctx, certificate)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, certificate)).To(Succeed())
			})

			Eventually(func(g Gomega) {
				Expect(testClient.Get(ctx, client.ObjectKeyFromObject(certificate), certificate)).To(Succeed())
				g.Expect(certificate.Status.State).To(Equal("Ready"))
			}).Should(Succeed())

			By("Resolve certificate secret reference")
			secretReference := certificate.Spec.SecretRef
			secretKey := client.ObjectKey{Name: secretReference.Name, Namespace: secretReference.Namespace}
			secret := &corev1.Secret{}
			Expect(testClient.Get(ctx, secretKey, secret)).To(Succeed())
			Expect(secret.Data).To(HaveKeyWithValue("ca.crt", Not(BeEmpty())))
			Expect(secret.Data).To(HaveKeyWithValue("tls.crt", Not(BeEmpty())))
			Expect(secret.Data).To(HaveKeyWithValue("tls.key", Not(BeEmpty())))
		})

		It("should not be able to create self-signed certificate if the duration is < 720h", func() {
			By("Create self-signed certificate")
			certificate := getCertificate(testRunID, "self-signed-certificate", "ca1.mydomain.com", issuer.Namespace, issuer.Name)
			certificate.Spec.IsCA = ptr.To(true)
			certificate.Spec.Duration = &metav1.Duration{Duration: 1 * time.Hour}
			Expect(testClient.Create(ctx, certificate)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, certificate)).To(Succeed())
			})

			Eventually(func(g Gomega) {
				Expect(testClient.Get(ctx, client.ObjectKeyFromObject(certificate), certificate)).To(Succeed())
				g.Expect(certificate.Status.State).To(Equal("Error"))
				g.Expect(certificate.Status.Message).To(PointTo(ContainSubstring("certificate duration must be greater than 1440h0m0s")))
			}).Should(Succeed())
		})

		It("should not be able to create self-signed certificate if IsCA = false", func() {
			By("Create self-signed certificate")
			certificate := getCertificate(testRunID, "self-signed-certificate", "ca1.mydomain.com", issuer.Namespace, issuer.Name)
			certificate.Spec.IsCA = ptr.To(false)
			Expect(testClient.Create(ctx, certificate)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, certificate)).To(Succeed())
			})

			Eventually(func(g Gomega) {
				Expect(testClient.Get(ctx, client.ObjectKeyFromObject(certificate), certificate)).To(Succeed())
				g.Expect(certificate.Status.State).To(Equal("Error"))
				g.Expect(certificate.Status.Message).To(PointTo(ContainSubstring("self signed certificates must set 'spec.isCA: true'")))
			}).Should(Succeed())
		})
	})

	Context("Certificate Authority issuer", func() {
		It("should be able to create CA issuer", func() {
			By("Get Certificate")
			priv, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())
			keyBytes := x509.MarshalPKCS1PrivateKey(priv)
			data, err := createPemCertificate(priv, priv.Public(), "RSA PRIVATE KEY", keyBytes)
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

			Eventually(func(g Gomega) {
				Expect(testClient.Get(ctx, client.ObjectKeyFromObject(issuer), issuer)).To(Succeed())
				g.Expect(issuer.Status.State).To(Equal("Ready"))
			}).Should(Succeed())
		})
	})
})

func getAcmeIssuer(namespace string, skipDnsChallengeValidation bool) *v1alpha1.Issuer {
	return &v1alpha1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "acme1",
		},
		Spec: v1alpha1.IssuerSpec{
			ACME: &v1alpha1.ACMESpec{
				Email:                      "foo@somewhere-foo-123456.com",
				Server:                     acmeDirectoryAddress,
				AutoRegistration:           true,
				SkipDNSChallengeValidation: ptr.To(skipDnsChallengeValidation),
			},
		},
	}
}

func getCertificate(certificateNamespace, certificateName, commonName, issuerNamespcae, issuerName string) *v1alpha1.Certificate {
	return &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: certificateNamespace,
			Name:      certificateName,
		},
		Spec: v1alpha1.CertificateSpec{
			CommonName: ptr.To(commonName),
			IssuerRef: &v1alpha1.IssuerRef{
				Namespace: issuerNamespcae,
				Name:      issuerName,
			},
		},
	}
}

func createPemCertificate(privKey crypto.PrivateKey, pubKey crypto.PublicKey, header string, privKeyBytes []byte) (map[string][]byte, error) {
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
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: header, Bytes: privKeyBytes})
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
		}
		runControllerManager(ctx, args)
	}()
}

func stopManager() {
	if ctx != nil {
		ctxutil.Cancel(ctx)
	}
}

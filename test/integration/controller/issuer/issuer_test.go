/*
 * // SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
 * //
 * // SPDX-License-Identifier: Apache-2.0
 */

package issuer_test

import (
	"context"
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
			cert := &v1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testRunID,
					Name:      "orphan-pending-certificate",
				},
				Spec: v1alpha1.CertificateSpec{
					CommonName: ptr.To("example.com"),
					IssuerRef: &v1alpha1.IssuerRef{
						Name: issuer.Name,
					},
				},
			}
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
			cert := &v1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testRunID,
					Name:      "certificate-with-unallowed-issuer",
				},
				Spec: v1alpha1.CertificateSpec{
					CommonName: ptr.To("example.com"),
					IssuerRef: &v1alpha1.IssuerRef{
						Namespace: "namespace1",
						Name:      "foo",
					},
				},
			}
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
	})

	Context("Self-signed issuer", func() {
		It("should be able to create self-signed certificates", func() {
			By("Create self-signed issuer")
			issuer := &v1alpha1.Issuer{
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

			By("Create self-signed certificate")
			certificate := &v1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testRunID,
					Name:      "self-signed-certificate",
				},
				Spec: v1alpha1.CertificateSpec{
					CommonName: ptr.To("ca1.mydomain.com"),
					IsCA:       ptr.To(true),
					IssuerRef: &v1alpha1.IssuerRef{
						Name:      issuer.Name,
						Namespace: issuer.Namespace,
					},
				},
			}
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
			By("Create self-signed issuer")
			issuer := &v1alpha1.Issuer{
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

			By("Create self-signed certificate")
			certificate := &v1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testRunID,
					Name:      "self-signed-certificate",
				},
				Spec: v1alpha1.CertificateSpec{
					CommonName: ptr.To("ca1.mydomain.com"),
					IsCA:       ptr.To(true),
					IssuerRef: &v1alpha1.IssuerRef{
						Name:      issuer.Name,
						Namespace: issuer.Namespace,
					},
					Duration: &metav1.Duration{Duration: 1 * time.Hour},
				},
			}
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
			By("Create self-signed issuer")
			issuer := &v1alpha1.Issuer{
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

			By("Create self-signed certificate")
			certificate := &v1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testRunID,
					Name:      "self-signed-certificate",
				},
				Spec: v1alpha1.CertificateSpec{
					CommonName: ptr.To("ca1.mydomain.com"),
					IsCA:       ptr.To(false),
					IssuerRef: &v1alpha1.IssuerRef{
						Name:      issuer.Name,
						Namespace: issuer.Namespace,
					},
				},
			}
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

	Context("RequestsPerDayQuota", func()  {
		
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
				Email:            "foo@somewhere-foo-123456.com",
				Server:           acmeDirectoryAddress,
				AutoRegistration: true,
				SkipDNSChallengeValidation: ptr.To(skipDnsChallengeValidation),
			},
		},
	}
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

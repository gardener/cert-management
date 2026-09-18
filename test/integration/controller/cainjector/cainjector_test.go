// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package cainjector_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	. "github.com/gardener/gardener/pkg/utils/test/matchers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	certv1alpha1 "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/controller/cainjector"
)

var _ = Describe("CA injector controller", func() {
	var (
		testNamespace *corev1.Namespace
		caBundle      []byte
		caSecret      *corev1.Secret
		certObj       *certv1alpha1.Certificate
	)

	BeforeEach(func() {
		ctxLocal := context.Background()

		By("Create test namespace")
		testNamespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "cainjector-"},
		}
		Expect(testClient.Create(ctxLocal, testNamespace)).To(Succeed())
		DeferCleanup(func() {
			Expect(testClient.Delete(ctxLocal, testNamespace)).To(Or(Succeed(), BeNotFoundError()))
		})

		By("Generate CA certificate")
		var err error
		caBundle, err = generateCACert()
		Expect(err).NotTo(HaveOccurred())

		By("Create CA secret with ca.crt")
		caSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "ca-secret-",
				Namespace:    testNamespace.Name,
			},
			Data: map[string][]byte{
				"ca.crt": caBundle,
			},
		}
		Expect(testClient.Create(ctxLocal, caSecret)).To(Succeed())
		DeferCleanup(func() {
			Expect(testClient.Delete(ctxLocal, caSecret)).To(Or(Succeed(), BeNotFoundError()))
		})

		By("Create Certificate pointing to the CA secret")
		// We bypass the issuer controller by manually specifying spec.secretName.
		// The CA injector resolves the CA via cert.Spec.SecretName → secret["ca.crt"].
		certObj = &certv1alpha1.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "cert-",
				Namespace:    testNamespace.Name,
			},
			Spec: certv1alpha1.CertificateSpec{
				SecretName: ptr.To(caSecret.Name),
				CommonName: ptr.To("test.example.com"),
			},
		}
		Expect(testClient.Create(ctxLocal, certObj)).To(Succeed())
		DeferCleanup(func() {
			Expect(testClient.Delete(ctxLocal, certObj)).To(Or(Succeed(), BeNotFoundError()))
		})

		By("Start manager")
		startManager()
		DeferCleanup(stopManager)
	})

	certRef := func() string {
		return testNamespace.Name + "/" + certObj.Name
	}

	Context("inject-ca-from annotation", func() {
		It("injects caBundle into MutatingWebhookConfiguration", func() {
			sideEffects := admissionregistrationv1.SideEffectClassNone
			failurePolicy := admissionregistrationv1.Ignore
			webhook := &admissionregistrationv1.MutatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-mwh-",
					Annotations: map[string]string{
						cainjector.AnnotationInjectCAFrom: certRef(),
					},
				},
				Webhooks: []admissionregistrationv1.MutatingWebhook{{
					Name:                    "test.example.com",
					AdmissionReviewVersions: []string{"v1"},
					ClientConfig:            admissionregistrationv1.WebhookClientConfig{URL: ptr.To("https://test.example.com/webhook")},
					SideEffects:             &sideEffects,
					FailurePolicy:           &failurePolicy,
				}},
			}
			Expect(testClient.Create(ctx, webhook)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, webhook)).To(Or(Succeed(), BeNotFoundError()))
			})

			Eventually(func(g Gomega) {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(webhook), webhook)).To(Succeed())
				g.Expect(webhook.Webhooks[0].ClientConfig.CABundle).To(Equal(caBundle))
			}).WithTimeout(10 * time.Second).Should(Succeed())
		})

		It("injects caBundle into ValidatingWebhookConfiguration", func() {
			sideEffects := admissionregistrationv1.SideEffectClassNone
			failurePolicy := admissionregistrationv1.Ignore
			webhook := &admissionregistrationv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-vwh-",
					Annotations: map[string]string{
						cainjector.AnnotationInjectCAFrom: certRef(),
					},
				},
				Webhooks: []admissionregistrationv1.ValidatingWebhook{{
					Name:                    "test.example.com",
					AdmissionReviewVersions: []string{"v1"},
					ClientConfig:            admissionregistrationv1.WebhookClientConfig{URL: ptr.To("https://test.example.com/webhook")},
					SideEffects:             &sideEffects,
					FailurePolicy:           &failurePolicy,
				}},
			}
			Expect(testClient.Create(ctx, webhook)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, webhook)).To(Or(Succeed(), BeNotFoundError()))
			})

			Eventually(func(g Gomega) {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(webhook), webhook)).To(Succeed())
				g.Expect(webhook.Webhooks[0].ClientConfig.CABundle).To(Equal(caBundle))
			}).WithTimeout(10 * time.Second).Should(Succeed())
		})

		It("injects caBundle into CRD conversion webhook", func() {
			crd := &apiextensionsv1.CustomResourceDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foos.cainjector-test.example.com",
					Annotations: map[string]string{
						cainjector.AnnotationInjectCAFrom: certRef(),
					},
				},
				Spec: apiextensionsv1.CustomResourceDefinitionSpec{
					Group: "cainjector-test.example.com",
					Names: apiextensionsv1.CustomResourceDefinitionNames{
						Plural: "foos", Singular: "foo", Kind: "Foo",
					},
					Scope: apiextensionsv1.NamespaceScoped,
					Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
						{Name: "v1", Served: true, Storage: true, Schema: &apiextensionsv1.CustomResourceValidation{
							OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{Type: "object"},
						}},
						{Name: "v1alpha1", Served: true, Storage: false, Schema: &apiextensionsv1.CustomResourceValidation{
							OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{Type: "object"},
						}},
					},
					Conversion: &apiextensionsv1.CustomResourceConversion{
						Strategy: apiextensionsv1.WebhookConverter,
						Webhook: &apiextensionsv1.WebhookConversion{
							ClientConfig:             &apiextensionsv1.WebhookClientConfig{URL: ptr.To("https://test.example.com/convert")},
							ConversionReviewVersions: []string{"v1"},
						},
					},
				},
			}
			Expect(testClient.Create(ctx, crd)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, crd)).To(Or(Succeed(), BeNotFoundError()))
			})

			Eventually(func(g Gomega) {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(crd), crd)).To(Succeed())
				g.Expect(crd.Spec.Conversion.Webhook.ClientConfig.CABundle).To(Equal(caBundle))
			}).WithTimeout(10 * time.Second).Should(Succeed())
		})
	})

	Context("inject-ca-from-secret annotation", func() {
		It("injects caBundle when the allow-direct-injection guard is set on the secret", func() {
			By("Set allow-direct-injection guard on the CA secret")
			secretPatch := caSecret.DeepCopy()
			secretPatch.Annotations = map[string]string{
				cainjector.AnnotationAllowDirectInjection: "true",
			}
			Expect(testClient.Update(ctx, secretPatch)).To(Succeed())

			sideEffects := admissionregistrationv1.SideEffectClassNone
			failurePolicy := admissionregistrationv1.Ignore
			webhook := &admissionregistrationv1.MutatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-mwh-direct-",
					Annotations: map[string]string{
						cainjector.AnnotationInjectCAFromSecret: testNamespace.Name + "/" + caSecret.Name,
					},
				},
				Webhooks: []admissionregistrationv1.MutatingWebhook{{
					Name:                    "test.example.com",
					AdmissionReviewVersions: []string{"v1"},
					ClientConfig:            admissionregistrationv1.WebhookClientConfig{URL: ptr.To("https://test.example.com/webhook")},
					SideEffects:             &sideEffects,
					FailurePolicy:           &failurePolicy,
				}},
			}
			Expect(testClient.Create(ctx, webhook)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, webhook)).To(Or(Succeed(), BeNotFoundError()))
			})

			Eventually(func(g Gomega) {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(webhook), webhook)).To(Succeed())
				g.Expect(webhook.Webhooks[0].ClientConfig.CABundle).To(Equal(caBundle))
			}).WithTimeout(10 * time.Second).Should(Succeed())
		})

		It("does not inject caBundle when the guard is missing", func() {
			sideEffects := admissionregistrationv1.SideEffectClassNone
			failurePolicy := admissionregistrationv1.Ignore
			webhook := &admissionregistrationv1.MutatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-mwh-noguard-",
					Annotations: map[string]string{
						cainjector.AnnotationInjectCAFromSecret: testNamespace.Name + "/" + caSecret.Name,
					},
				},
				Webhooks: []admissionregistrationv1.MutatingWebhook{{
					Name:                    "test.example.com",
					AdmissionReviewVersions: []string{"v1"},
					ClientConfig:            admissionregistrationv1.WebhookClientConfig{URL: ptr.To("https://test.example.com/webhook")},
					SideEffects:             &sideEffects,
					FailurePolicy:           &failurePolicy,
				}},
			}
			Expect(testClient.Create(ctx, webhook)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, webhook)).To(Or(Succeed(), BeNotFoundError()))
			})

			Consistently(func(g Gomega) {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(webhook), webhook)).To(Succeed())
				g.Expect(webhook.Webhooks[0].ClientConfig.CABundle).To(BeEmpty())
			}).Within(3 * time.Second).Should(Succeed())
		})
	})
})

func generateCACert() ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}

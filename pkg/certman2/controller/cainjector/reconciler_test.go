// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package cainjector_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	certmanclient "github.com/gardener/cert-management/pkg/certman2/client"
	"github.com/gardener/cert-management/pkg/certman2/controller/cainjector"
)

var _ = Describe("CA Injector Reconciler", func() {
	var (
		ctx        context.Context
		fakeClient client.Client
	)

	BeforeEach(func() {
		ctx = context.TODO()
		fakeClient = fakeclient.NewClientBuilder().WithScheme(certmanclient.ClusterScheme).Build()
	})

	Describe("ValidatingWebhookConfiguration", func() {
		It("patches caBundle from inject-ca-from Certificate", func() {
			caBytes := []byte("fake-ca-cert")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "cert-ns", Name: "my-cert-secret"},
				Data:       map[string][]byte{"ca.crt": caBytes},
			}
			cert := &v1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "cert-ns", Name: "my-cert"},
				Spec:       v1alpha1.CertificateSpec{SecretName: strPtr("my-cert-secret")},
			}
			vwc := &admissionv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "my-vwc",
					Annotations: map[string]string{
						"cert.gardener.cloud/inject-ca-from": "cert-ns/my-cert",
					},
				},
				Webhooks: []admissionv1.ValidatingWebhook{
					{Name: "hook1.example.com", ClientConfig: admissionv1.WebhookClientConfig{}},
					{Name: "hook2.example.com", ClientConfig: admissionv1.WebhookClientConfig{}},
				},
			}
			Expect(fakeClient.Create(ctx, secret)).To(Succeed())
			Expect(fakeClient.Create(ctx, cert)).To(Succeed())
			Expect(fakeClient.Create(ctx, vwc)).To(Succeed())

			r := &cainjector.Reconciler{Client: fakeClient}
			result, err := r.ReconcileValidatingWebhookConfiguration(ctx, reconcile.Request{
				NamespacedName: client.ObjectKeyFromObject(vwc),
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))

			Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(vwc), vwc)).To(Succeed())
			for _, wh := range vwc.Webhooks {
				Expect(wh.ClientConfig.CABundle).To(Equal(caBytes), "webhook %s should have caBundle set", wh.Name)
			}
		})

		It("patches caBundle directly from inject-ca-from-secret with allow annotation", func() {
			caBytes := []byte("direct-ca-cert")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "cert-ns",
					Name:      "my-secret",
					Annotations: map[string]string{
						"cert.gardener.cloud/allow-direct-injection": "true",
					},
				},
				Data: map[string][]byte{"ca.crt": caBytes},
			}
			vwc := &admissionv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "my-vwc2",
					Annotations: map[string]string{
						"cert.gardener.cloud/inject-ca-from-secret": "cert-ns/my-secret",
					},
				},
				Webhooks: []admissionv1.ValidatingWebhook{
					{Name: "hook.example.com", ClientConfig: admissionv1.WebhookClientConfig{}},
				},
			}
			Expect(fakeClient.Create(ctx, secret)).To(Succeed())
			Expect(fakeClient.Create(ctx, vwc)).To(Succeed())

			r := &cainjector.Reconciler{Client: fakeClient}
			result, err := r.ReconcileValidatingWebhookConfiguration(ctx, reconcile.Request{
				NamespacedName: client.ObjectKeyFromObject(vwc),
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))

			Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(vwc), vwc)).To(Succeed())
			Expect(vwc.Webhooks[0].ClientConfig.CABundle).To(Equal(caBytes))
		})

		It("refuses inject-ca-from-secret without allow-direct-injection annotation", func() {
			caBytes := []byte("direct-ca-cert")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "cert-ns", Name: "restricted-secret"},
				Data:       map[string][]byte{"ca.crt": caBytes},
			}
			vwc := &admissionv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "my-vwc3",
					Annotations: map[string]string{
						"cert.gardener.cloud/inject-ca-from-secret": "cert-ns/restricted-secret",
					},
				},
				Webhooks: []admissionv1.ValidatingWebhook{
					{Name: "hook.example.com", ClientConfig: admissionv1.WebhookClientConfig{}},
				},
			}
			Expect(fakeClient.Create(ctx, secret)).To(Succeed())
			Expect(fakeClient.Create(ctx, vwc)).To(Succeed())

			r := &cainjector.Reconciler{Client: fakeClient}
			result, err := r.ReconcileValidatingWebhookConfiguration(ctx, reconcile.Request{
				NamespacedName: client.ObjectKeyFromObject(vwc),
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))

			// caBundle must NOT be patched
			Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(vwc), vwc)).To(Succeed())
			Expect(vwc.Webhooks[0].ClientConfig.CABundle).To(BeNil())
		})

		It("leaves target unchanged and requeues when ca.crt is missing", func() {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "cert-ns", Name: "empty-secret"},
				Data:       map[string][]byte{}, // no ca.crt
			}
			cert := &v1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "cert-ns", Name: "empty-cert"},
				Spec:       v1alpha1.CertificateSpec{SecretName: strPtr("empty-secret")},
			}
			vwc := &admissionv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "my-vwc4",
					Annotations: map[string]string{
						"cert.gardener.cloud/inject-ca-from": "cert-ns/empty-cert",
					},
				},
				Webhooks: []admissionv1.ValidatingWebhook{
					{Name: "hook.example.com", ClientConfig: admissionv1.WebhookClientConfig{}},
				},
			}
			Expect(fakeClient.Create(ctx, secret)).To(Succeed())
			Expect(fakeClient.Create(ctx, cert)).To(Succeed())
			Expect(fakeClient.Create(ctx, vwc)).To(Succeed())

			r := &cainjector.Reconciler{Client: fakeClient}
			result, err := r.ReconcileValidatingWebhookConfiguration(ctx, reconcile.Request{
				NamespacedName: client.ObjectKeyFromObject(vwc),
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0), "should requeue when CA is unavailable")

			// target must remain unchanged
			Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(vwc), vwc)).To(Succeed())
			Expect(vwc.Webhooks[0].ClientConfig.CABundle).To(BeNil())
		})
	})

	Describe("MutatingWebhookConfiguration", func() {
		It("patches all webhook entries from inject-ca-from", func() {
			caBytes := []byte("mutating-ca")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "cert-ns", Name: "mut-secret"},
				Data:       map[string][]byte{"ca.crt": caBytes},
			}
			cert := &v1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "cert-ns", Name: "mut-cert"},
				Spec:       v1alpha1.CertificateSpec{SecretName: strPtr("mut-secret")},
			}
			mwc := &admissionv1.MutatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: "my-mwc",
					Annotations: map[string]string{
						"cert.gardener.cloud/inject-ca-from": "cert-ns/mut-cert",
					},
				},
				Webhooks: []admissionv1.MutatingWebhook{
					{Name: "hook1.example.com", ClientConfig: admissionv1.WebhookClientConfig{}},
					{Name: "hook2.example.com", ClientConfig: admissionv1.WebhookClientConfig{}},
				},
			}
			Expect(fakeClient.Create(ctx, secret)).To(Succeed())
			Expect(fakeClient.Create(ctx, cert)).To(Succeed())
			Expect(fakeClient.Create(ctx, mwc)).To(Succeed())

			r := &cainjector.Reconciler{Client: fakeClient}
			result, err := r.ReconcileMutatingWebhookConfiguration(ctx, reconcile.Request{
				NamespacedName: client.ObjectKeyFromObject(mwc),
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))

			Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(mwc), mwc)).To(Succeed())
			for _, wh := range mwc.Webhooks {
				Expect(wh.ClientConfig.CABundle).To(Equal(caBytes), "webhook %s should have caBundle", wh.Name)
			}
		})
	})

	Describe("CustomResourceDefinition", func() {
		It("patches conversion webhook caBundle from inject-ca-from", func() {
			caBytes := []byte("crd-ca")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "cert-ns", Name: "crd-secret"},
				Data:       map[string][]byte{"ca.crt": caBytes},
			}
			cert := &v1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "cert-ns", Name: "crd-cert"},
				Spec:       v1alpha1.CertificateSpec{SecretName: strPtr("crd-secret")},
			}
			crd := makeCRD("my-crd", "cert-ns/crd-cert")
			Expect(fakeClient.Create(ctx, secret)).To(Succeed())
			Expect(fakeClient.Create(ctx, cert)).To(Succeed())
			Expect(fakeClient.Create(ctx, crd)).To(Succeed())

			r := &cainjector.Reconciler{Client: fakeClient}
			result, err := r.ReconcileCustomResourceDefinition(ctx, reconcile.Request{
				NamespacedName: client.ObjectKeyFromObject(crd),
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))

			Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(crd), crd)).To(Succeed())
			Expect(crd.Spec.Conversion.Webhook.ClientConfig.CABundle).To(Equal(caBytes))
		})
	})

	Describe("APIService", func() {
		It("patches spec.caBundle from inject-ca-from", func() {
			caBytes := []byte("apiservice-ca")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "cert-ns", Name: "api-secret"},
				Data:       map[string][]byte{"ca.crt": caBytes},
			}
			cert := &v1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{Namespace: "cert-ns", Name: "api-cert"},
				Spec:       v1alpha1.CertificateSpec{SecretName: strPtr("api-secret")},
			}
			apiSvc := makeAPIService("v1alpha1.example.com", "cert-ns/api-cert")
			Expect(fakeClient.Create(ctx, secret)).To(Succeed())
			Expect(fakeClient.Create(ctx, cert)).To(Succeed())
			Expect(fakeClient.Create(ctx, apiSvc)).To(Succeed())

			r := &cainjector.Reconciler{Client: fakeClient}
			result, err := r.ReconcileAPIService(ctx, reconcile.Request{
				NamespacedName: client.ObjectKeyFromObject(apiSvc),
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))

			Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(apiSvc), apiSvc)).To(Succeed())
			Expect(apiSvc.Spec.CABundle).To(Equal(caBytes))
		})
	})
})

func strPtr(s string) *string { return &s }

func makeCRD(name, injectFrom string) *apiextensionsv1.CustomResourceDefinition {
	strategy := apiextensionsv1.WebhookConverter
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Annotations: map[string]string{
				"cert.gardener.cloud/inject-ca-from": injectFrom,
			},
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "example.com",
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Plural: "foos", Singular: "foo", Kind: "Foo",
			},
			Scope: apiextensionsv1.ClusterScoped,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
				{Name: "v1alpha1", Served: true, Storage: true,
					Schema: &apiextensionsv1.CustomResourceValidation{
						OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{Type: "object"},
					}},
			},
			Conversion: &apiextensionsv1.CustomResourceConversion{
				Strategy: strategy,
				Webhook: &apiextensionsv1.WebhookConversion{
					ClientConfig: &apiextensionsv1.WebhookClientConfig{},
				},
			},
		},
	}
}

func makeAPIService(name, injectFrom string) *apiregistrationv1.APIService {
	return &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Annotations: map[string]string{
				"cert.gardener.cloud/inject-ca-from": injectFrom,
			},
		},
		Spec: apiregistrationv1.APIServiceSpec{
			Group:                "example.com",
			Version:              "v1alpha1",
			GroupPriorityMinimum: 100,
			VersionPriority:      100,
		},
	}
}

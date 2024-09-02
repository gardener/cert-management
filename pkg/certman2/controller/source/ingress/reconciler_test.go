package ingress_test

import (
	"context"
	"fmt"
	"strings"
	"time"

	certmanv1alpha1 "github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	certmanclient "github.com/gardener/cert-management/pkg/certman2/client"
	"github.com/gardener/cert-management/pkg/certman2/controller/source"
	. "github.com/gardener/cert-management/pkg/certman2/controller/source/ingress"
)

const longDomain = "a-long-long-domain-name-with-more-than-63-characters.example.com"

var _ = Describe("Reconciler", func() {
	var (
		ctx          = context.Background()
		fakeClient   client.Client
		fakeRecorder *record.FakeRecorder
		ingress      *networkingv1.Ingress
		cert         *certmanv1alpha1.Certificate
		reconciler   *Reconciler

		testWithoutCreation = func(specs []*certmanv1alpha1.CertificateSpec, expectedErrorMessage ...string) {
			req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: ingress.Namespace, Name: ingress.Name}}
			_, err := reconciler.Reconcile(ctx, req)
			if len(expectedErrorMessage) > 0 {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(expectedErrorMessage[0]))
				return
			}
			Expect(err).NotTo(HaveOccurred())

			list := certmanv1alpha1.CertificateList{}
			Expect(fakeClient.List(ctx, &list, client.InNamespace("test"))).NotTo(HaveOccurred())
			var items []certmanv1alpha1.Certificate
			for _, item := range list.Items {
				for _, owner := range item.OwnerReferences {
					if owner.Name == ingress.Name {
						items = append(items, item)
					}
				}
			}
			Expect(items).To(HaveLen(len(specs)))
			if len(specs) == 0 {
				return
			}
			for _, certSpec := range specs {
				found := false
				for _, cert := range items {
					if cert.Spec.SecretRef.Name == certSpec.SecretRef.Name {
						found = true
						Expect(cert.Namespace).To(Equal("test"))
						Expect(cert.Name).To(ContainSubstring("foo-ingress-"))
						Expect(cert.OwnerReferences).To(HaveLen(1))
						Expect(cert.OwnerReferences[0]).To(MatchFields(IgnoreExtras, Fields{
							"APIVersion": Equal("networking.k8s.io/v1"),
							"Kind":       Equal("Ingress"),
							"Name":       Equal("foo"),
							"Controller": PointTo(BeTrue()),
						}))
						Expect(cert.Spec).To(Equal(*certSpec))
						break
					}
				}
				Expect(found).To(BeTrue(), certSpec.SecretRef.Name)
			}
		}

		test = func(spec *certmanv1alpha1.CertificateSpec, expectedErrorMessage ...string) {
			Expect(fakeClient.Create(ctx, ingress)).NotTo(HaveOccurred())
			var specs []*certmanv1alpha1.CertificateSpec
			if spec != nil {
				specs = []*certmanv1alpha1.CertificateSpec{spec}
			}
			testWithoutCreation(specs, expectedErrorMessage...)
		}

		testMulti = func(specs ...*certmanv1alpha1.CertificateSpec) {
			Expect(fakeClient.Create(ctx, ingress)).NotTo(HaveOccurred())
			testWithoutCreation(specs)
		}
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().WithScheme(certmanclient.ClusterScheme).Build()
		reconciler = &Reconciler{}
		reconciler.Client = fakeClient
		reconciler.Complete()
		fakeRecorder = record.NewFakeRecorder(32)
		reconciler.Recorder = fakeRecorder
		ingress = &networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo",
				Namespace: "test",
				Annotations: map[string]string{
					source.AnnotationPurposeKey: source.AnnotationPurposeValueManaged,
					source.AnnotDnsnames:        "*",
				},
			},
			Spec: networkingv1.IngressSpec{
				TLS: []networkingv1.IngressTLS{
					{
						Hosts:      []string{"host1.example.com"},
						SecretName: "host1-secret",
					},
				},
			},
		}
		cert = &certmanv1alpha1.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo-ingress-1",
				Namespace: "test",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         "networking.k8s.io/v1",
						Kind:               "Ingress",
						Name:               "foo",
						UID:                "123-456",
						Controller:         ptr.To(true),
						BlockOwnerDeletion: ptr.To(true),
					},
				},
			},
		}
	})

	AfterEach(func() {
		close(fakeRecorder.Events)
	})

	Describe("#Reconcile", func() {
		It("should create certificate object for ingress with TLS", func() {
			test(&certmanv1alpha1.CertificateSpec{
				CommonName: ptr.To("host1.example.com"),
				SecretRef:  &corev1.SecretReference{Name: "host1-secret", Namespace: "test"},
			})
			assertEvents(fakeRecorder.Events, "Normal CertificateCreated ")
		})

		It("should drop certificate object if no TLS set", func() {
			Expect(fakeClient.Create(ctx, cert)).NotTo(HaveOccurred())
			ingress.Spec.TLS = nil
			test(nil)
			assertEvents(fakeRecorder.Events, "Normal CertificateDeleted ")
		})

		It("should create invalid certificate if no hosts are set", func() {
			ingress.Spec.TLS[0].Hosts = nil
			test(&certmanv1alpha1.CertificateSpec{
				SecretRef: &corev1.SecretReference{Name: "host1-secret", Namespace: "test"},
			})
			assertEvents(fakeRecorder.Events, "Normal CertificateCreated ")
		})

		It("should succeed if '*' dnsnames is overwritten by cert dnsnames", func() {
			ingress.Annotations[source.AnnotCertDNSNames] = "foo.cert.example.com,foo-alt.cert.example.com"
			test(&certmanv1alpha1.CertificateSpec{
				CommonName: ptr.To("foo.cert.example.com"),
				DNSNames:   []string{"foo-alt.cert.example.com"},
				SecretRef:  &corev1.SecretReference{Name: "host1-secret", Namespace: "test"},
			})
			assertEvents(fakeRecorder.Events, "Normal CertificateCreated ")
		})

		It("should create correct certificate object  with common name", func() {
			ingress.Annotations[source.AnnotDnsnames] = "*"
			ingress.Annotations[source.AnnotCommonName] = "foo.example.com"
			test(&certmanv1alpha1.CertificateSpec{
				CommonName: ptr.To("foo.example.com"),
				DNSNames:   []string{"host1.example.com"},
				SecretRef:  &corev1.SecretReference{Name: "host1-secret", Namespace: "test"},
			})
			assertEvents(fakeRecorder.Events, "Normal CertificateCreated")
		})

		It("should create correct certificate object if common name with cert annotation", func() {
			ingress.Annotations[source.AnnotCommonName] = "foo.cert.example.com"
			ingress.Annotations[source.AnnotCertDNSNames] = "foo-alt.cert.example.com"
			test(&certmanv1alpha1.CertificateSpec{
				CommonName: ptr.To("foo.cert.example.com"),
				DNSNames:   []string{"foo-alt.cert.example.com"},
				SecretRef:  &corev1.SecretReference{Name: "host1-secret", Namespace: "test"},
			})
		})

		It("should update certificate object for service of type load balancer with additional fields", func() {
			ingress.Annotations[source.AnnotCertDNSNames] = fmt.Sprintf("foo1.%s,foo2.%s", longDomain, longDomain)
			ingress.Annotations[source.AnnotClass] = source.DefaultClass
			ingress.Annotations[source.AnnotIssuer] = "my-ns/my-issuer"
			ingress.Annotations[source.AnnotFollowCNAME] = "true"
			ingress.Annotations[source.AnnotCertSecretLabels] = "key1=value1,key2=value2"
			ingress.Annotations[source.AnnotDNSRecordProviderType] = "local"
			ingress.Annotations[source.AnnotDNSRecordSecretRef] = "my-provider-ns/my-provider-secret"
			ingress.Annotations[source.AnnotPreferredChain] = "my-chain"
			ingress.Annotations[source.AnnotPrivateKeyAlgorithm] = "ECDSA"
			ingress.Annotations[source.AnnotPrivateKeySize] = "384"
			cert.Spec.SecretName = ptr.To("host1-secret")
			Expect(fakeClient.Create(ctx, cert)).NotTo(HaveOccurred())
			test(&certmanv1alpha1.CertificateSpec{
				CommonName:   nil,
				DNSNames:     []string{"foo1." + longDomain, "foo2." + longDomain},
				SecretRef:    &corev1.SecretReference{Name: "host1-secret", Namespace: "test"},
				SecretLabels: map[string]string{"key1": "value1", "key2": "value2"},
				IssuerRef: &certmanv1alpha1.IssuerRef{
					Name:      "my-issuer",
					Namespace: "my-ns",
				},
				FollowCNAME:    ptr.To(true),
				PreferredChain: ptr.To("my-chain"),
				PrivateKey: &certmanv1alpha1.CertificatePrivateKey{
					Algorithm: ptr.To(certmanv1alpha1.ECDSAKeyAlgorithm),
					Size:      ptr.To[certmanv1alpha1.PrivateKeySize](384),
				},
			})
			Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(cert), cert)).NotTo(HaveOccurred())
			Expect(cert.Annotations).To(Equal(map[string]string{source.AnnotClass: "gardencert", source.AnnotDNSRecordProviderType: "local", source.AnnotDNSRecordSecretRef: "my-provider-ns/my-provider-secret"}))
			assertEvents(fakeRecorder.Events, "Normal CertificateUpdated ")
		})

		It("should keep certificate object and drop obsolete ones", func() {
			cert2 := cert.DeepCopy()
			cert3 := cert.DeepCopy()
			Expect(fakeClient.Create(ctx, cert)).NotTo(HaveOccurred())
			cert2.Name = "foo-ingress-2"
			cert2.Spec = certmanv1alpha1.CertificateSpec{
				CommonName: ptr.To("host1.example.com"),
				SecretRef:  &corev1.SecretReference{Name: "host1-secret", Namespace: "test"},
			}
			Expect(fakeClient.Create(ctx, cert2)).NotTo(HaveOccurred())
			cert3.Name = "other-service"
			cert3.OwnerReferences[0].Name = "other"
			cert3.ResourceVersion = ""
			Expect(fakeClient.Create(ctx, cert3)).NotTo(HaveOccurred())
			test(&certmanv1alpha1.CertificateSpec{
				CommonName: ptr.To("host1.example.com"),
				SecretRef:  &corev1.SecretReference{Name: "host1-secret", Namespace: "test"},
			})
			Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(cert2), &certmanv1alpha1.Certificate{})).NotTo(HaveOccurred())
			Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(cert3), &certmanv1alpha1.Certificate{})).NotTo(HaveOccurred())
			assertEvents(fakeRecorder.Events, "Normal CertificateDeleted ")
		})

		It("should create multiple certificates for multiple TLS", func() {
			ingress.Spec.TLS = []networkingv1.IngressTLS{
				{
					Hosts:      []string{"host1.example.com", "host1-alt.example.com"},
					SecretName: "host1-secret",
				},
				{
					Hosts:      []string{"host2.example.com"},
					SecretName: "host2-secret",
				},
			}
			testMulti(
				&certmanv1alpha1.CertificateSpec{
					CommonName: ptr.To("host1.example.com"),
					DNSNames:   []string{"host1-alt.example.com"},
					SecretRef:  &corev1.SecretReference{Name: "host1-secret", Namespace: "test"},
				},
				&certmanv1alpha1.CertificateSpec{
					CommonName: ptr.To("host2.example.com"),
					SecretRef:  &corev1.SecretReference{Name: "host2-secret", Namespace: "test"},
				})
			assertEvents(fakeRecorder.Events, "Normal CertificateCreated ", "Normal CertificateCreated ")

			ingress.Spec.TLS = []networkingv1.IngressTLS{
				{
					Hosts:      []string{"host1.example.com", "host1.other.example.com"},
					SecretName: "host1-secret",
				},
				{
					Hosts:      []string{"host3.example.com"},
					SecretName: "host3-secret",
				},
			}
			Expect(fakeClient.Update(ctx, ingress)).NotTo(HaveOccurred())
			testWithoutCreation([]*certmanv1alpha1.CertificateSpec{
				{
					CommonName: ptr.To("host1.example.com"),
					DNSNames:   []string{"host1.other.example.com"},
					SecretRef:  &corev1.SecretReference{Name: "host1-secret", Namespace: "test"},
				},
				{
					CommonName: ptr.To("host3.example.com"),
					SecretRef:  &corev1.SecretReference{Name: "host3-secret", Namespace: "test"},
				},
			})
			assertEvents(fakeRecorder.Events, "Normal CertificateDeleted ", "Normal CertificateUpdated ", "Normal CertificateCreated ")
		})

		It("should delete certificate object if ingress TLS is dropped", func() {
			test(&certmanv1alpha1.CertificateSpec{
				CommonName: ptr.To("host1.example.com"),
				SecretRef:  &corev1.SecretReference{Name: "host1-secret", Namespace: "test"},
			})
			ingress.Spec.TLS = nil
			Expect(fakeClient.Update(ctx, ingress)).NotTo(HaveOccurred())
			testWithoutCreation(nil)
			assertEvents(fakeRecorder.Events, "Normal CertificateCreated ", "Normal CertificateDeleted ")
		})
	})
})

func assertEvents(actual <-chan string, expected ...string) {
	c := time.After(1 * time.Second)
	for _, e := range expected {
		select {
		case a := <-actual:
			if !strings.HasPrefix(a, e) {
				Expect(a).To(ContainSubstring(e))
				return
			}
		case <-c:
			Fail(fmt.Sprintf("Expected event %q, got nothing", e))
			// continue iterating to print all expected events
		}
	}
	for {
		select {
		case a := <-actual:
			Fail(fmt.Sprintf("Unexpected event: %q", a))
		default:
			return // No more events, as expected.
		}
	}
}

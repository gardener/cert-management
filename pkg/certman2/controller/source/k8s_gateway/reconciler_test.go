package k8s_gateway

import (
	"context"
	"fmt"

	"github.com/gardener/cert-management/pkg/certman2/testutils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayapisv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapisv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	certmanv1alpha1 "github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
	certmanclient "github.com/gardener/cert-management/pkg/certman2/client"
	"github.com/gardener/cert-management/pkg/certman2/controller/source"
)

const longDomain = "a-long-long-domain-name-with-more-than-63-characters.example.com"

func createReconcilerTestFunc[T client.Object](obj T, version Version) func() {
	return func() {
		var (
			ctx          = context.Background()
			fakeClient   client.Client
			fakeRecorder *record.FakeRecorder
			gateway      T
			cert         *certmanv1alpha1.Certificate
			reconciler   *Reconciler

			testWithoutCreation = func(specs []*certmanv1alpha1.CertificateSpec, expectedErrorMessage ...string) {
				req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: gateway.GetNamespace(), Name: gateway.GetName()}}
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
						if owner.Name == gateway.GetName() {
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
							Expect(cert.Name).To(ContainSubstring("foo-gateway-"))
							Expect(cert.OwnerReferences).To(HaveLen(1))
							Expect(cert.OwnerReferences[0]).To(MatchFields(IgnoreExtras, Fields{
								"APIVersion": Equal("gateway.networking.k8s.io/" + string(version)),
								"Kind":       Equal("Gateway"),
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
				Expect(fakeClient.Create(ctx, gateway)).NotTo(HaveOccurred())
				var specs []*certmanv1alpha1.CertificateSpec
				if spec != nil {
					specs = []*certmanv1alpha1.CertificateSpec{spec}
				}
				testWithoutCreation(specs, expectedErrorMessage...)
			}

			testMulti = func(specs ...*certmanv1alpha1.CertificateSpec) {
				Expect(fakeClient.Create(ctx, gateway)).NotTo(HaveOccurred())
				testWithoutCreation(specs)
			}
		)

		BeforeEach(func() {
			fakeClient = fakeclient.NewClientBuilder().WithScheme(certmanclient.ClusterScheme).Build()
			reconciler = &Reconciler{}
			reconciler.Client = fakeClient
			reconciler.ActiveVersion = version
			reconciler.Complete()
			fakeRecorder = record.NewFakeRecorder(32)
			reconciler.Recorder = fakeRecorder
			gateway = obj.DeepCopyObject().(T)
			gateway.SetNamespace("test")
			gateway.SetName("foo")
			gateway.SetAnnotations(map[string]string{
				source.AnnotationPurposeKey: source.AnnotationPurposeValueManaged,
				source.AnnotDnsnames:        "*",
			})
			modifyListeners(gateway, func([]gatewayapisv1.Listener) []gatewayapisv1.Listener {
				return []gatewayapisv1.Listener{
					{
						Hostname: ptr.To[gatewayapisv1.Hostname]("host1.example.com"),
						Protocol: gatewayapisv1.HTTPSProtocolType,
						TLS: &gatewayapisv1.GatewayTLSConfig{
							CertificateRefs: []gatewayapisv1.SecretObjectReference{
								{Name: "host1-secret"},
							},
						},
					},
				}
			})
			cert = &certmanv1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo-gateway-1",
					Namespace: "test",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "gateway.networking.k8s.io/" + string(version),
							Kind:               "Gateway",
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
			It("should create certificate object for gateway with TLS", func() {
				test(&certmanv1alpha1.CertificateSpec{
					CommonName: ptr.To("host1.example.com"),
					SecretRef:  &corev1.SecretReference{Name: "host1-secret", Namespace: "test"},
				})
				testutils.AssertEvents(fakeRecorder.Events, "Normal CertificateCreated ")
			})

			It("should drop certificate object if no TLS set", func() {
				Expect(fakeClient.Create(ctx, cert)).NotTo(HaveOccurred())
				modifyListeners(gateway, func(listeners []gatewayapisv1.Listener) []gatewayapisv1.Listener {
					listeners[0].TLS = nil
					return listeners
				})
				test(nil)
				testutils.AssertEvents(fakeRecorder.Events, "Normal CertificateDeleted ")
			})

			It("should create invalid certificate if no hostname is set", func() {
				modifyListeners(gateway, func(listeners []gatewayapisv1.Listener) []gatewayapisv1.Listener {
					listeners[0].Hostname = nil
					return listeners
				})
				test(&certmanv1alpha1.CertificateSpec{
					SecretRef: &corev1.SecretReference{Name: "host1-secret", Namespace: "test"},
				})
				testutils.AssertEvents(fakeRecorder.Events, "Normal CertificateCreated ")
			})

			It("should succeed if '*' dnsnames is overwritten by cert dnsnames", func() {
				gateway.GetAnnotations()[source.AnnotCertDNSNames] = "foo.cert.example.com,foo-alt.cert.example.com"
				test(&certmanv1alpha1.CertificateSpec{
					CommonName: ptr.To("foo.cert.example.com"),
					DNSNames:   []string{"foo-alt.cert.example.com"},
					SecretRef:  &corev1.SecretReference{Name: "host1-secret", Namespace: "test"},
				})
				testutils.AssertEvents(fakeRecorder.Events, "Normal CertificateCreated ")
			})

			It("should create correct certificate object  with common name", func() {
				gateway.GetAnnotations()[source.AnnotDnsnames] = "*"
				gateway.GetAnnotations()[source.AnnotCommonName] = "foo.example.com"
				test(&certmanv1alpha1.CertificateSpec{
					CommonName: ptr.To("foo.example.com"),
					DNSNames:   []string{"host1.example.com"},
					SecretRef:  &corev1.SecretReference{Name: "host1-secret", Namespace: "test"},
				})
				testutils.AssertEvents(fakeRecorder.Events, "Normal CertificateCreated")
			})

			It("should create correct certificate object if common name with cert annotation", func() {
				gateway.GetAnnotations()[source.AnnotCommonName] = "foo.cert.example.com"
				gateway.GetAnnotations()[source.AnnotCertDNSNames] = "foo-alt.cert.example.com"
				test(&certmanv1alpha1.CertificateSpec{
					CommonName: ptr.To("foo.cert.example.com"),
					DNSNames:   []string{"foo-alt.cert.example.com"},
					SecretRef:  &corev1.SecretReference{Name: "host1-secret", Namespace: "test"},
				})
			})

			It("should update certificate object for service of type load balancer with additional fields", func() {
				annotations := gateway.GetAnnotations()
				annotations[source.AnnotCertDNSNames] = fmt.Sprintf("foo1.%s,foo2.%s", longDomain, longDomain)
				annotations[source.AnnotClass] = source.DefaultClass
				annotations[source.AnnotIssuer] = "my-ns/my-issuer"
				annotations[source.AnnotFollowCNAME] = "true"
				annotations[source.AnnotCertSecretLabels] = "key1=value1,key2=value2"
				annotations[source.AnnotDNSRecordProviderType] = "local"
				annotations[source.AnnotDNSRecordSecretRef] = "my-provider-ns/my-provider-secret"
				annotations[source.AnnotPreferredChain] = "my-chain"
				annotations[source.AnnotPrivateKeyAlgorithm] = "ECDSA"
				annotations[source.AnnotPrivateKeySize] = "384"
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
				testutils.AssertEvents(fakeRecorder.Events, "Normal CertificateUpdated ")
			})

			It("should keep certificate object and drop obsolete ones", func() {
				cert2 := cert.DeepCopy()
				cert3 := cert.DeepCopy()
				Expect(fakeClient.Create(ctx, cert)).NotTo(HaveOccurred())
				cert2.Name = "foo-gateway-2"
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
				testutils.AssertEvents(fakeRecorder.Events, "Normal CertificateDeleted ")
			})

			It("should create multiple certificates for multiple TLS", func() {
				modifyListeners(gateway, func([]gatewayapisv1.Listener) []gatewayapisv1.Listener {
					return []gatewayapisv1.Listener{
						{
							Hostname: ptr.To[gatewayapisv1.Hostname]("host1.example.com"),
							Protocol: gatewayapisv1.HTTPSProtocolType,
							TLS: &gatewayapisv1.GatewayTLSConfig{
								CertificateRefs: []gatewayapisv1.SecretObjectReference{
									{Name: "host1-secret"},
								},
							},
						},
						{
							Hostname: ptr.To[gatewayapisv1.Hostname]("host2.example.com"),
							Protocol: gatewayapisv1.HTTPSProtocolType,
							TLS: &gatewayapisv1.GatewayTLSConfig{
								CertificateRefs: []gatewayapisv1.SecretObjectReference{
									{Name: "host2-secret"},
								},
							},
						},
					}
				})
				testMulti(
					&certmanv1alpha1.CertificateSpec{
						CommonName: ptr.To("host1.example.com"),
						SecretRef:  &corev1.SecretReference{Name: "host1-secret", Namespace: "test"},
					},
					&certmanv1alpha1.CertificateSpec{
						CommonName: ptr.To("host2.example.com"),
						SecretRef:  &corev1.SecretReference{Name: "host2-secret", Namespace: "test"},
					})
				testutils.AssertEvents(fakeRecorder.Events, "Normal CertificateCreated ", "Normal CertificateCreated ")

				modifyListeners(gateway, func(listeners []gatewayapisv1.Listener) []gatewayapisv1.Listener {
					listeners[0].Hostname = ptr.To[gatewayapisv1.Hostname]("host1b.example.com")
					listeners[1].Hostname = ptr.To[gatewayapisv1.Hostname]("host3.example.com")
					listeners[1].TLS = &gatewayapisv1.GatewayTLSConfig{
						CertificateRefs: []gatewayapisv1.SecretObjectReference{
							{Name: "host3-secret"},
						},
					}
					return listeners
				})
				Expect(fakeClient.Update(ctx, gateway)).NotTo(HaveOccurred())
				testWithoutCreation([]*certmanv1alpha1.CertificateSpec{
					{
						CommonName: ptr.To("host1b.example.com"),
						SecretRef:  &corev1.SecretReference{Name: "host1-secret", Namespace: "test"},
					},
					{
						CommonName: ptr.To("host3.example.com"),
						SecretRef:  &corev1.SecretReference{Name: "host3-secret", Namespace: "test"},
					},
				})
				testutils.AssertUnorderedEvents(fakeRecorder.Events, "Normal CertificateDeleted ", "Normal CertificateUpdated ", "Normal CertificateCreated ")
			})

			It("should delete certificate object if gateway TLS is dropped", func() {
				test(&certmanv1alpha1.CertificateSpec{
					CommonName: ptr.To("host1.example.com"),
					SecretRef:  &corev1.SecretReference{Name: "host1-secret", Namespace: "test"},
				})
				modifyListeners(gateway, func(listeners []gatewayapisv1.Listener) []gatewayapisv1.Listener {
					listeners[0].TLS = nil
					return listeners
				})
				Expect(fakeClient.Update(ctx, gateway)).NotTo(HaveOccurred())
				testWithoutCreation(nil)
				testutils.AssertEvents(fakeRecorder.Events, "Normal CertificateCreated ", "Normal CertificateDeleted ")
			})
		})
	}
}

var (
	_ = Describe("Reconciler-v1", createReconcilerTestFunc(newGateway(VersionV1), VersionV1))
	_ = Describe("Reconciler-v1beta1", createReconcilerTestFunc(newGateway(VersionV1beta1), VersionV1beta1))
)

func modifyListeners(gateway client.Object, modifier func(listeners []gatewayapisv1.Listener) []gatewayapisv1.Listener) {
	switch g := gateway.(type) {
	case *gatewayapisv1.Gateway:
		g.Spec.Listeners = modifier(g.Spec.Listeners)
	case *gatewayapisv1beta1.Gateway:
		var input []gatewayapisv1.Listener
		if len(g.Spec.Listeners) > 0 {
			data, err := json.Marshal(g.Spec.Listeners)
			Expect(err).NotTo(HaveOccurred())
			err = json.Unmarshal(data, &input)
			Expect(err).NotTo(HaveOccurred())
		}
		output := modifier(input)
		if len(output) > 0 {
			data, err := json.Marshal(output)
			Expect(err).NotTo(HaveOccurred())
			var tmp []gatewayapisv1beta1.Listener
			err = json.Unmarshal(data, &tmp)
			Expect(err).NotTo(HaveOccurred())
			g.Spec.Listeners = tmp
		} else {
			g.Spec.Listeners = nil
		}
	default:
		Fail("unexpected type")
	}
}

// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package source_test

import (
	"context"
	"reflect"

	. "github.com/gardener/gardener/pkg/utils/test/matchers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	istioapinetworkingv1 "istio.io/api/networking/v1"
	istionetworkingv1 "istio.io/client-go/pkg/apis/networking/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/rest"
	componentbaseconfig "k8s.io/component-base/config"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	gatewayapisv1 "sigs.k8s.io/gateway-api/apis/v1"

	certmanv1alpha1 "github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/certman2/apis/config"
	certmanclient "github.com/gardener/cert-management/pkg/certman2/client"
	"github.com/gardener/cert-management/pkg/certman2/controller/source"
	"github.com/gardener/cert-management/pkg/certman2/controller/source/add"
)

var _ = Describe("Source controller tests", func() {
	var (
		testRunID     string
		testNamespace *corev1.Namespace

		certificateGarbageCollection = func(obj client.Object) {
			list := &certmanv1alpha1.CertificateList{}
			Expect(testClient.List(ctx, list, client.InNamespace(testRunID))).To(Succeed())
			for _, cert := range list.Items {
				Expect(simulateGC(&cert, obj)).To(Succeed())
			}
		}
	)

	BeforeEach(func() {
		By("Create test Namespace")
		testNamespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "source-",
			},
		}
		Expect(testClient.Create(ctx, testNamespace)).To(Succeed())
		log.Info("Created Namespace for test", "namespaceName", testNamespace.Name)
		testRunID = testNamespace.Name

		DeferCleanup(func() {
			By("Delete test Namespace")
			Expect(testClient.Delete(ctx, testNamespace)).To(Or(Succeed(), BeNotFoundError()))
		})

		By("Setup manager")
		httpClient, err := rest.HTTPClientFor(restConfig)
		Expect(err).NotTo(HaveOccurred())
		mapper, err := apiutil.NewDynamicRESTMapper(restConfig, httpClient)
		Expect(err).NotTo(HaveOccurred())

		mgr, err := manager.New(restConfig, manager.Options{
			Scheme:  scheme,
			Metrics: metricsserver.Options{BindAddress: "0"},
			Cache: cache.Options{
				Mapper: mapper,
				ByObject: map[client.Object]cache.ByObject{
					&corev1.Service{}: {
						Namespaces: map[string]cache.Config{testRunID: {}},
					},
					&networkingv1.Ingress{}: {
						Namespaces: map[string]cache.Config{testRunID: {}},
					},
					&istionetworkingv1.Gateway{}: {
						Namespaces: map[string]cache.Config{testRunID: {}},
					},
					&istionetworkingv1.VirtualService{}: {
						Namespaces: map[string]cache.Config{testRunID: {}},
					},
					&gatewayapisv1.Gateway{}: {
						Namespaces: map[string]cache.Config{testRunID: {}},
					},
					&gatewayapisv1.HTTPRoute{}: {
						Namespaces: map[string]cache.Config{testRunID: {}},
					},
					&certmanv1alpha1.Certificate{}: {
						Namespaces: map[string]cache.Config{testRunID: {}},
					},
					&apiextensionsv1.CustomResourceDefinition{}: {},
				},
			},
		})
		Expect(err).NotTo(HaveOccurred())
		mgrClient = mgr.GetClient()

		cfg := &config.CertManagerConfiguration{
			LeaderElection: componentbaseconfig.LeaderElectionConfiguration{
				LeaderElect: false,
			},
			Class:    testRunID,
			LogLevel: "debug",
		}
		By("Register source controllers")
		tmpClient, err := client.New(restConfig, client.Options{
			Scheme: certmanclient.ClusterScheme,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(add.AddToManager(mgr, cfg, tmpClient)).To(Succeed())

		By("Start manager")
		mgrContext, mgrCancel := context.WithCancel(ctx)

		go func() {
			defer GinkgoRecover()
			Expect(mgr.Start(mgrContext)).To(Succeed())
		}()

		DeferCleanup(func() {
			By("Stop manager")
			mgrCancel()
		})
	})

	It("should successfully reconcile a service of type LoadBalancer", func() {
		service := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-service",
				Namespace: testRunID,
				Annotations: map[string]string{
					source.AnnotSecretname: "test-service-secret",
					source.AnnotDnsnames:   "test.example.com,test.alt.example.com",
					source.AnnotClass:      testRunID,
				},
			},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{
					{
						Name: "https",
						Port: 443,
					},
				},
				Type: corev1.ServiceTypeLoadBalancer,
			},
		}
		Expect(testClient.Create(ctx, service)).To(Succeed())
		DeferCleanup(func() {
			certificateGarbageCollection(service)
		})

		By("Wait for certificate")
		Eventually(func(g Gomega) {
			checkCertificateSpec(g, service, certmanv1alpha1.CertificateSpec{
				CommonName: ptr.To("test.example.com"),
				DNSNames:   []string{"test.alt.example.com"},
				SecretRef: &corev1.SecretReference{
					Name:      "test-service-secret",
					Namespace: testRunID,
				},
			})
		}).Should(Succeed())

		Expect(testClient.Delete(ctx, service)).To(Succeed())
	})

	It("should successfully reconcile an ingress", func() {
		ingress := &networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-ingress",
				Namespace: testRunID,
				Annotations: map[string]string{
					source.AnnotationPurposeKey: source.AnnotationPurposeValueManaged,
					source.AnnotClass:           testRunID,
				},
			},
			Spec: networkingv1.IngressSpec{
				TLS: []networkingv1.IngressTLS{
					{
						Hosts:      []string{"test.example.com", "test.alt.example.com"},
						SecretName: "test-ingress-secret",
					},
				},
				Rules: []networkingv1.IngressRule{
					{
						Host:             "test.example.com",
						IngressRuleValue: networkingv1.IngressRuleValue{},
					},
					{
						Host:             "test.alt.example.com",
						IngressRuleValue: networkingv1.IngressRuleValue{},
					},
				},
			},
		}
		Expect(testClient.Create(ctx, ingress)).To(Succeed())
		DeferCleanup(func() {
			certificateGarbageCollection(ingress)
		})

		By("Wait for certificate")
		Eventually(func(g Gomega) {
			checkCertificateSpec(g, ingress, certmanv1alpha1.CertificateSpec{
				CommonName: ptr.To("test.example.com"),
				DNSNames:   []string{"test.alt.example.com"},
				SecretRef: &corev1.SecretReference{
					Name:      "test-ingress-secret",
					Namespace: testRunID,
				},
			})
		}).Should(Succeed())

		Expect(testClient.Delete(ctx, ingress)).To(Succeed())
	})

	It("should successfully reconcile an Istio gateway", func() {
		gateway := &istionetworkingv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-gateway",
				Namespace: testRunID,
				Annotations: map[string]string{
					source.AnnotationPurposeKey: source.AnnotationPurposeValueManaged,
					source.AnnotClass:           testRunID,
				},
			},
			Spec: istioapinetworkingv1.Gateway{
				Servers: []*istioapinetworkingv1.Server{
					{
						Hosts: []string{"test.example.com", "test.alt.example.com"},
						Port: &istioapinetworkingv1.Port{
							Number:   443,
							Protocol: "TCP",
							Name:     "https",
						},
						Tls: &istioapinetworkingv1.ServerTLSSettings{
							Mode:           istioapinetworkingv1.ServerTLSSettings_SIMPLE,
							CredentialName: "test-gateway-credential",
						},
					},
				},
			},
		}
		Expect(testClient.Create(ctx, gateway)).To(Succeed())
		DeferCleanup(func() {
			certificateGarbageCollection(gateway)
		})

		By("Wait for certificate")
		Eventually(func(g Gomega) {
			checkCertificateSpec(g, gateway, certmanv1alpha1.CertificateSpec{
				CommonName: ptr.To("test.example.com"),
				DNSNames:   []string{"test.alt.example.com"},
				SecretRef: &corev1.SecretReference{
					Name:      "test-gateway-credential",
					Namespace: testRunID,
				},
			})
		}).Should(Succeed())

		Expect(testClient.Delete(ctx, gateway)).To(Succeed())
	})

	It("should successfully reconcile an Istio gateway with virtual services", func() {
		gateway := &istionetworkingv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-gateway",
				Namespace: testRunID,
				Annotations: map[string]string{
					source.AnnotationPurposeKey: source.AnnotationPurposeValueManaged,
					source.AnnotClass:           testRunID,
				},
			},
			Spec: istioapinetworkingv1.Gateway{
				Servers: []*istioapinetworkingv1.Server{
					{
						Hosts: []string{"*"},
						Port: &istioapinetworkingv1.Port{
							Number:   443,
							Protocol: "TCP",
							Name:     "https",
						},
						Tls: &istioapinetworkingv1.ServerTLSSettings{
							Mode:           istioapinetworkingv1.ServerTLSSettings_SIMPLE,
							CredentialName: "test-gateway-credential",
						},
					},
				},
			},
		}
		Expect(testClient.Create(ctx, gateway)).To(Succeed())

		vs1 := &istionetworkingv1.VirtualService{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-vs1",
				Namespace: testRunID,
			},
			Spec: istioapinetworkingv1.VirtualService{
				Hosts:    []string{"vs1.example.com"},
				Gateways: []string{gateway.Name},
			},
		}
		Expect(testClient.Create(ctx, vs1)).To(Succeed())
		DeferCleanup(func() {
			certificateGarbageCollection(gateway)
		})

		expectedCertSpec := certmanv1alpha1.CertificateSpec{
			CommonName: ptr.To("vs1.example.com"),
			SecretRef: &corev1.SecretReference{
				Name:      "test-gateway-credential",
				Namespace: testRunID,
			},
		}

		By("Wait for certificate")
		Eventually(func(g Gomega) {
			checkCertificateSpec(g, gateway, expectedCertSpec)
		}).Should(Succeed())

		vs2 := &istionetworkingv1.VirtualService{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-vs2",
				Namespace: testRunID,
			},
			Spec: istioapinetworkingv1.VirtualService{
				Hosts:    []string{"vs2.example.com"},
				Gateways: []string{gateway.Name},
			},
		}
		Expect(testClient.Create(ctx, vs2)).To(Succeed())

		By("Wait for updated certificate")
		expectedCertSpec.DNSNames = []string{"vs2.example.com"}
		Eventually(func(g Gomega) {
			checkCertificateSpec(g, gateway, expectedCertSpec)
		}).Should(Succeed())

		vs2.Spec.Hosts = []string{"vs2b.example.com"}
		Expect(testClient.Update(ctx, vs2)).To(Succeed())

		By("Wait for updated certificate")
		expectedCertSpec.DNSNames = []string{"vs2b.example.com"}
		Eventually(func(g Gomega) {
			checkCertificateSpec(g, gateway, expectedCertSpec)
		}).Should(Succeed())

		vs2.Spec.Gateways = nil
		Expect(testClient.Update(ctx, vs2)).To(Succeed())

		By("Wait for updated certificate")
		expectedCertSpec.DNSNames = nil
		Eventually(func(g Gomega) {
			checkCertificateSpec(g, gateway, expectedCertSpec)
		}).Should(Succeed())

		Expect(testClient.Delete(ctx, vs1)).To(Succeed())
		Expect(testClient.Delete(ctx, vs2)).To(Succeed())

		expectedCertSpec.CommonName = nil
		expectedCertSpec.DNSNames = nil
		Eventually(func(g Gomega) {
			checkCertificateSpec(g, gateway, expectedCertSpec)
		}).Should(Succeed())

		Expect(testClient.Delete(ctx, gateway)).To(Succeed())
	})

	It("should successfully reconcile an Kubernetes gateway", func() {
		gateway := &gatewayapisv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-gateway",
				Namespace: testRunID,
				Annotations: map[string]string{
					source.AnnotationPurposeKey: source.AnnotationPurposeValueManaged,
					source.AnnotClass:           testRunID,
				},
			},
			Spec: gatewayapisv1.GatewaySpec{
				GatewayClassName: "foo",
				Listeners: []gatewayapisv1.Listener{
					{
						Name:     "l1",
						Port:     443,
						Hostname: ptr.To[gatewayapisv1.Hostname]("test.example.com"),
						Protocol: gatewayapisv1.HTTPSProtocolType,
						TLS: &gatewayapisv1.GatewayTLSConfig{
							CertificateRefs: []gatewayapisv1.SecretObjectReference{
								{Name: "test-gateway-credential"},
							},
						},
					},
				},
			},
		}
		Expect(testClient.Create(ctx, gateway)).To(Succeed())
		DeferCleanup(func() {
			certificateGarbageCollection(gateway)
		})

		By("Wait for certificate")
		Eventually(func(g Gomega) {
			checkCertificateSpec(g, gateway, certmanv1alpha1.CertificateSpec{
				CommonName: ptr.To("test.example.com"),
				SecretRef: &corev1.SecretReference{
					Name:      "test-gateway-credential",
					Namespace: testRunID,
				},
			})
		}).Should(Succeed())

		Expect(testClient.Delete(ctx, gateway)).To(Succeed())
	})

	It("should successfully reconcile an Kubernetes gateway with HTTP routes", func() {
		gateway := &gatewayapisv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-gateway",
				Namespace: testRunID,
				Annotations: map[string]string{
					source.AnnotationPurposeKey: source.AnnotationPurposeValueManaged,
					source.AnnotClass:           testRunID,
				},
			},
			Spec: gatewayapisv1.GatewaySpec{
				GatewayClassName: "foo",
				Listeners: []gatewayapisv1.Listener{
					{
						Name:     "l1",
						Port:     443,
						Protocol: gatewayapisv1.HTTPSProtocolType,
						TLS: &gatewayapisv1.GatewayTLSConfig{
							CertificateRefs: []gatewayapisv1.SecretObjectReference{
								{Name: "test-gateway-credential"},
							},
						},
					},
				},
			},
		}
		Expect(testClient.Create(ctx, gateway)).To(Succeed())

		parentRef := gatewayapisv1.ParentReference{
			Namespace: ptr.To(gatewayapisv1.Namespace(gateway.Namespace)),
			Name:      gatewayapisv1.ObjectName(gateway.Name),
		}
		route1 := &gatewayapisv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-route1",
				Namespace: testRunID,
			},
			Spec: gatewayapisv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayapisv1.CommonRouteSpec{
					ParentRefs: []gatewayapisv1.ParentReference{parentRef},
				},
				Hostnames: []gatewayapisv1.Hostname{"route1.example.com"},
			},
			Status: gatewayapisv1.HTTPRouteStatus{
				RouteStatus: gatewayapisv1.RouteStatus{
					Parents: []gatewayapisv1.RouteParentStatus{
						{
							ParentRef:      parentRef,
							ControllerName: "example.net/gateway-controller",
						},
					},
				},
			},
		}
		Expect(testClient.Create(ctx, route1)).To(Succeed())
		DeferCleanup(func() {
			certificateGarbageCollection(gateway)
		})

		expectedCertSpec := certmanv1alpha1.CertificateSpec{
			CommonName: ptr.To("route1.example.com"),
			SecretRef: &corev1.SecretReference{
				Name:      "test-gateway-credential",
				Namespace: testRunID,
			},
		}

		By("Wait for certificate")
		Eventually(func(g Gomega) {
			checkCertificateSpec(g, gateway, expectedCertSpec)
		}).Should(Succeed())

		route2 := &gatewayapisv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-route2",
				Namespace: testRunID,
			},
			Spec: gatewayapisv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayapisv1.CommonRouteSpec{
					ParentRefs: []gatewayapisv1.ParentReference{parentRef},
				},
				Hostnames: []gatewayapisv1.Hostname{"route2.example.com"},
			},
			Status: gatewayapisv1.HTTPRouteStatus{
				RouteStatus: gatewayapisv1.RouteStatus{
					Parents: []gatewayapisv1.RouteParentStatus{
						{
							ParentRef:      parentRef,
							ControllerName: "example.net/gateway-controller",
						},
					},
				},
			},
		}
		Expect(testClient.Create(ctx, route2)).To(Succeed())

		By("Wait for updated certificate")
		expectedCertSpec.DNSNames = []string{"route2.example.com"}
		Eventually(func(g Gomega) {
			checkCertificateSpec(g, gateway, expectedCertSpec)
		}).Should(Succeed())

		route2.Spec.Hostnames = []gatewayapisv1.Hostname{"route2.example.com", "route2b.example.com"}
		Expect(testClient.Update(ctx, route2)).To(Succeed())

		By("Wait for updated certificate")
		expectedCertSpec.DNSNames = []string{"route2.example.com", "route2b.example.com"}
		Eventually(func(g Gomega) {
			checkCertificateSpec(g, gateway, expectedCertSpec)
		}).Should(Succeed())

		Expect(testClient.Delete(ctx, route2)).To(Succeed())

		By("Wait for updated certificate")
		expectedCertSpec.DNSNames = nil
		Eventually(func(g Gomega) {
			checkCertificateSpec(g, gateway, expectedCertSpec)
		}).Should(Succeed())

		Expect(testClient.Delete(ctx, route1)).To(Succeed())

		expectedCertSpec.CommonName = nil
		Eventually(func(g Gomega) {
			checkCertificateSpec(g, gateway, expectedCertSpec)
		}).Should(Succeed())

		Expect(testClient.Delete(ctx, gateway)).To(Succeed())
	})
})

func checkCertificateSpec(g Gomega, obj client.Object, expectedSpec certmanv1alpha1.CertificateSpec) {
	gvks, _, err := testClient.Scheme().ObjectKinds(obj)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(gvks).To(HaveLen(1))
	gvk := gvks[0]

	list := &certmanv1alpha1.CertificateList{}
	g.Expect(testClient.List(ctx, list, client.InNamespace(obj.GetNamespace()))).To(Succeed())
	g.Expect(list.Items).To(HaveLen(1))
	cert := list.Items[0]
	g.Expect(cert.OwnerReferences).To(Equal([]metav1.OwnerReference{
		{
			APIVersion:         gvk.GroupVersion().String(),
			Kind:               gvk.Kind,
			Name:               obj.GetName(),
			UID:                obj.GetUID(),
			Controller:         ptr.To(true),
			BlockOwnerDeletion: ptr.To(true),
		},
	}))
	if !reflect.DeepEqual(expectedSpec, cert.Spec) {
		expectedNames := collectDNSNames(expectedSpec)
		actualNames := collectDNSNames(cert.Spec)
		g.Expect(actualNames).To(Equal(expectedNames))
		expectedSpecCopy := *expectedSpec.DeepCopy()
		expectedSpecCopy.CommonName = cert.Spec.CommonName
		expectedSpecCopy.DNSNames = cert.Spec.DNSNames
		g.Expect(cert.Spec).To(Equal(expectedSpecCopy))
	} else {
		g.Expect(cert.Spec).To(Equal(expectedSpec))
	}
}

func simulateGC(obj, owner client.Object) error {
	gvks, _, err := testClient.Scheme().ObjectKinds(obj)
	Expect(err).NotTo(HaveOccurred())
	Expect(gvks).To(HaveLen(1))
	gvk := gvks[0]

	for _, ref := range obj.GetOwnerReferences() {
		if ref.UID == owner.GetUID() && ref.Kind == gvk.Kind {
			// simulate Kubernetes garbage collection (see https://github.com/kubernetes-sigs/kubebuilder/blob/master/docs/book/src/reference/envtest.md#testing-considerations)
			return testClient.Delete(ctx, obj)
		}
	}
	return nil
}

func collectDNSNames(spec certmanv1alpha1.CertificateSpec) sets.Set[string] {
	names := sets.Set[string]{}
	if spec.CommonName != nil {
		names.Insert(*spec.CommonName)
	}
	names.Insert(spec.DNSNames...)
	return names
}

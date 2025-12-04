// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package k8s_gateway

import (
	"context"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayapisv1 "sigs.k8s.io/gateway-api/apis/v1"

	certmanclient "github.com/gardener/cert-management/pkg/certman2/client"
	"github.com/gardener/cert-management/pkg/certman2/controller/source/common"
)

var _ = Describe("Reconciler", func() {
	var (
		ctx                = context.Background()
		log                = logr.Discard()
		emptyMap           = common.CertInputMap{}
		standardObjectMeta = metav1.ObjectMeta{
			Namespace: "test",
			Name:      "g1",
			Annotations: map[string]string{
				common.AnnotationPurposeKey: common.AnnotationPurposeValueManaged,
			},
		}
		fakeClient client.Client
		reconciler *Reconciler

		allRoutes = func() []*gatewayapisv1.HTTPRoute {
			route1 := &gatewayapisv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test",
					Name:      "route1",
				},
				Spec: gatewayapisv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayapisv1.CommonRouteSpec{ParentRefs: []gatewayapisv1.ParentReference{
						{
							Namespace: ptr.To[gatewayapisv1.Namespace]("test"),
							Name:      "g1",
						},
					}},
					Hostnames: []gatewayapisv1.Hostname{"foo.example.com", "bar.example.com"},
				},
			}
			route2 := &gatewayapisv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test",
					Name:      "route2",
				},
				Spec: gatewayapisv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayapisv1.CommonRouteSpec{ParentRefs: []gatewayapisv1.ParentReference{
						{
							Namespace: ptr.To[gatewayapisv1.Namespace]("test"),
							Name:      "g1",
						},
					}},
					Hostnames: []gatewayapisv1.Hostname{"foo.example.com"},
				},
			}
			route3 := &gatewayapisv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test",
					Name:      "route3",
				},
				Spec: gatewayapisv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayapisv1.CommonRouteSpec{ParentRefs: []gatewayapisv1.ParentReference{
						{
							Namespace: ptr.To[gatewayapisv1.Namespace]("test"),
							Name:      "g2",
						},
					}},
					Hostnames: []gatewayapisv1.Hostname{"bla.example.com"},
				},
			}
			return []*gatewayapisv1.HTTPRoute{route1, route2, route3}
		}
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().WithScheme(certmanclient.ClusterScheme).Build()
		reconciler = &Reconciler{}
		reconciler.Client = fakeClient
		reconciler.ActiveVersion = VersionV1
		reconciler.Complete()
	})

	_ = DescribeTable("#getCertificateInputMap",
		func(gateway *gatewayapisv1.Gateway, httpRoutes []*gatewayapisv1.HTTPRoute, expectedMap common.CertInputMap) {
			for _, route := range httpRoutes {
				Expect(fakeClient.Create(ctx, route)).NotTo(HaveOccurred(), route.Name)
			}
			actualMap, err := reconciler.getCertificateInputMap(ctx, log, gateway)
			if err != nil {
				if expectedMap != nil {
					Fail("unexpected error: " + err.Error())
				}
				return
			}
			if expectedMap == nil {
				Fail("expected error, but got CertsInputMap")
				return
			}
			if len(actualMap) == 0 {
				actualMap = common.CertInputMap{}
			}
			Expect(actualMap).To(Equal(expectedMap))
		},
		Entry("should be empty if there are no listeners", &gatewayapisv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec:       gatewayapisv1.GatewaySpec{},
		}, nil, emptyMap),
		Entry("should have empty info if there are no TLS config", &gatewayapisv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: gatewayapisv1.GatewaySpec{
				Listeners: []gatewayapisv1.Listener{
					{
						Hostname: ptr.To[gatewayapisv1.Hostname]("a.example.com"),
					},
				},
			},
		}, nil, emptyMap),
		Entry("should have empty info if multiple certificate refs are provided", &gatewayapisv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: gatewayapisv1.GatewaySpec{
				Listeners: []gatewayapisv1.Listener{
					{
						Hostname: ptr.To[gatewayapisv1.Hostname]("a.example.com"),
						TLS: &gatewayapisv1.ListenerTLSConfig{
							CertificateRefs: []gatewayapisv1.SecretObjectReference{
								{Name: "foo"},
								{Name: "bar"},
							},
						},
					},
				},
			},
		}, nil, emptyMap),
		Entry("should have empty info if certificate ref with custom object is provided", &gatewayapisv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: gatewayapisv1.GatewaySpec{
				Listeners: []gatewayapisv1.Listener{
					{
						Hostname: ptr.To[gatewayapisv1.Hostname]("a.example.com"),
						TLS: &gatewayapisv1.ListenerTLSConfig{
							CertificateRefs: []gatewayapisv1.SecretObjectReference{
								{Kind: ptr.To(gatewayapisv1.Kind("MySpecialKind")), Name: "foo"},
							},
						},
					},
				},
			},
		}, nil, emptyMap),
		Entry("should have empty certsInfo info if protocol is HTTP", &gatewayapisv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: gatewayapisv1.GatewaySpec{
				Listeners: []gatewayapisv1.Listener{
					{
						Hostname: ptr.To[gatewayapisv1.Hostname]("a.example.com"),
						Protocol: gatewayapisv1.HTTPProtocolType,
						TLS: &gatewayapisv1.ListenerTLSConfig{
							CertificateRefs: []gatewayapisv1.SecretObjectReference{
								{Name: "foo"},
							},
						},
					},
				},
			},
		}, nil, emptyMap),
		Entry("should have empty certsInfo info if tls mode is passthrough", &gatewayapisv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: gatewayapisv1.GatewaySpec{
				Listeners: []gatewayapisv1.Listener{
					{
						Hostname: ptr.To[gatewayapisv1.Hostname]("a.example.com"),
						Protocol: gatewayapisv1.HTTPSProtocolType,
						TLS: &gatewayapisv1.ListenerTLSConfig{
							Mode: ptr.To(gatewayapisv1.TLSModePassthrough),
							CertificateRefs: []gatewayapisv1.SecretObjectReference{
								{Name: "foo"},
							},
						},
					},
				},
			},
		}, nil, emptyMap),
		Entry("should have single certsInfo info if single certificate is provided and protocol is HTTPS", &gatewayapisv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: gatewayapisv1.GatewaySpec{
				Listeners: []gatewayapisv1.Listener{
					{
						Hostname: ptr.To[gatewayapisv1.Hostname]("a.example.com"),
						Protocol: gatewayapisv1.HTTPSProtocolType,
						TLS: &gatewayapisv1.ListenerTLSConfig{
							CertificateRefs: []gatewayapisv1.SecretObjectReference{
								{Namespace: ptr.To(gatewayapisv1.Namespace("ns1")), Name: "foo"},
							},
						},
					},
				},
			},
		}, nil, singleCertInput("foo", ptr.To("ns1"), "a.example.com")),
		Entry("should have single certsInfo info if single certificate is provided and protocol is TLSProtocolType", &gatewayapisv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: gatewayapisv1.GatewaySpec{
				Listeners: []gatewayapisv1.Listener{
					{
						Hostname: ptr.To[gatewayapisv1.Hostname]("a.example.com"),
						Protocol: gatewayapisv1.TLSProtocolType,
						TLS: &gatewayapisv1.ListenerTLSConfig{
							CertificateRefs: []gatewayapisv1.SecretObjectReference{
								{Name: "foo"},
							},
						},
					},
				},
			},
		}, nil, singleCertInput("foo", nil, "a.example.com")),
		Entry("gateway with multiple listeners", &gatewayapisv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: gatewayapisv1.GatewaySpec{
				Listeners: []gatewayapisv1.Listener{
					{
						Hostname: ptr.To[gatewayapisv1.Hostname]("a.example.com"),
						Protocol: gatewayapisv1.HTTPSProtocolType,
						TLS: &gatewayapisv1.ListenerTLSConfig{
							CertificateRefs: []gatewayapisv1.SecretObjectReference{
								{Name: "foo1"},
							},
						},
					},
					{
						Hostname: ptr.To[gatewayapisv1.Hostname]("b.example.com"),
						Protocol: gatewayapisv1.HTTPSProtocolType,
						TLS: &gatewayapisv1.ListenerTLSConfig{
							CertificateRefs: []gatewayapisv1.SecretObjectReference{
								{Name: "foo2"},
							},
						},
					},
				},
			},
		}, nil, toMap(
			makeCertInput("foo1", nil, "a.example.com"),
			makeCertInput("foo2", nil, "b.example.com"),
		)),
		Entry("assigned gateway to service with wildcard hostname and HTTPRoutes", &gatewayapisv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: gatewayapisv1.GatewaySpec{
				Listeners: []gatewayapisv1.Listener{
					{
						Hostname: ptr.To[gatewayapisv1.Hostname]("*.example.com"),
						Protocol: gatewayapisv1.HTTPSProtocolType,
						TLS: &gatewayapisv1.ListenerTLSConfig{
							CertificateRefs: []gatewayapisv1.SecretObjectReference{
								{Name: "foo"},
							},
						},
					},
				},
			},
		}, allRoutes(), singleCertInput("foo", nil, "*.example.com")),
		Entry("assigned gateway to service with hostname and HTTPRoutes", &gatewayapisv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: gatewayapisv1.GatewaySpec{
				Listeners: []gatewayapisv1.Listener{
					{
						Hostname: ptr.To[gatewayapisv1.Hostname]("b.example.com"),
						Protocol: gatewayapisv1.HTTPSProtocolType,
						TLS: &gatewayapisv1.ListenerTLSConfig{
							CertificateRefs: []gatewayapisv1.SecretObjectReference{
								{Name: "foo"},
							},
						},
					},
				},
			},
		}, allRoutes(), singleCertInput("foo", nil, "b.example.com", "foo.example.com", "bar.example.com")),
		Entry("hosts in cert annotation override all hosts", &gatewayapisv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test",
				Name:      "g1",
				Annotations: map[string]string{
					common.AnnotCertDNSNames:    "a.example.com,c.example.com",
					common.AnnotationPurposeKey: common.AnnotationPurposeValueManaged,
				},
			},
			Spec: gatewayapisv1.GatewaySpec{
				Listeners: []gatewayapisv1.Listener{
					{
						Hostname: ptr.To[gatewayapisv1.Hostname]("b.example.com"),
						Protocol: gatewayapisv1.HTTPSProtocolType,
						TLS: &gatewayapisv1.ListenerTLSConfig{
							CertificateRefs: []gatewayapisv1.SecretObjectReference{
								{Name: "foo"},
							},
						},
					},
				},
			},
		}, allRoutes(), singleCertInput("foo", nil, "a.example.com", "c.example.com")),
		Entry("check various cert annotations", &gatewayapisv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test",
				Name:      "g1",
				Annotations: map[string]string{
					common.AnnotationPurposeKey:       common.AnnotationPurposeValueManaged,
					common.AnnotPreferredChain:        "chain2",
					common.AnnotCommonName:            "a.example.com",
					common.AnnotCertDNSNames:          "c.example.com,d.example.com",
					common.AnnotIssuer:                "test-issuer",
					common.AnnotPrivateKeyAlgorithm:   "ECDSA",
					common.AnnotPrivateKeySize:        "384",
					common.AnnotCertSecretLabels:      "a=b, c=bar42",
					common.AnnotDNSRecordProviderType: "dummy-type",
					common.AnnotDNSRecordSecretRef:    "dummy",
				},
			},
			Spec: gatewayapisv1.GatewaySpec{
				Listeners: []gatewayapisv1.Listener{
					{
						Hostname: ptr.To[gatewayapisv1.Hostname]("b.example.com"),
						Protocol: gatewayapisv1.HTTPSProtocolType,
						TLS: &gatewayapisv1.ListenerTLSConfig{
							CertificateRefs: []gatewayapisv1.SecretObjectReference{
								{Name: "foo"},
							},
						},
					},
				},
			},
		}, allRoutes(), toMap(modifyCertInput(makeCertInput("foo", nil, "a.example.com", "c.example.com", "d.example.com"), func(info common.CertInput) common.CertInput {
			info.PreferredChain = "chain2"
			info.PrivateKeyAlgorithm = "ECDSA"
			info.PrivateKeySize = 384
			info.IssuerName = ptr.To("test-issuer")
			info.SecretLabels = map[string]string{"a": "b", "c": "bar42"}
			info.Annotations = map[string]string{
				common.AnnotDNSRecordProviderType: "dummy-type",
				common.AnnotDNSRecordSecretRef:    "dummy",
			}
			return info
		}))))
})

func singleCertInput(secretName string, ns *string, names ...string) common.CertInputMap {
	info := makeCertInput(secretName, ns, names...)
	return toMap(info)
}

func toMap(inputs ...common.CertInput) common.CertInputMap {
	result := common.CertInputMap{}
	for _, input := range inputs {
		result[input.SecretObjectKey] = input
	}
	return result
}

func makeCertInput(secretName string, ns *string, names ...string) common.CertInput {
	namespace := "test"
	if ns != nil {
		namespace = *ns
	}
	return common.CertInput{
		SecretObjectKey: client.ObjectKey{Namespace: namespace, Name: secretName},
		Domains:         names,
	}
}

func modifyCertInput(input common.CertInput, modifier func(common.CertInput) common.CertInput) common.CertInput {
	return modifier(input)
}

// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package gatewayapi

import (
	"github.com/gardener/cert-management/pkg/cert/source"
	ctrlsource "github.com/gardener/cert-management/pkg/controller/source"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gatewayapisv1 "sigs.k8s.io/gateway-api/apis/v1"
)

var _ = Describe("Kubernetes Networking Gateway Handler", func() {
	var (
		route1 = &gatewayapisv1.HTTPRoute{
			Spec: gatewayapisv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayapisv1.CommonRouteSpec{ParentRefs: []gatewayapisv1.ParentReference{
					{
						Namespace: ptr.To(gatewayapisv1.Namespace("test")),
						Name:      "g1",
					},
				}},
				Hostnames: []gatewayapisv1.Hostname{"foo.example.com", "bar.example.com"},
			},
		}
		route2 = &gatewayapisv1.HTTPRoute{
			Spec: gatewayapisv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayapisv1.CommonRouteSpec{ParentRefs: []gatewayapisv1.ParentReference{
					{
						Namespace: ptr.To(gatewayapisv1.Namespace("test")),
						Name:      "g1",
					},
				}},
				Hostnames: []gatewayapisv1.Hostname{"foo.example.com"},
			},
		}
		route3 = &gatewayapisv1.HTTPRoute{
			Spec: gatewayapisv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayapisv1.CommonRouteSpec{ParentRefs: []gatewayapisv1.ParentReference{
					{
						Namespace: ptr.To(gatewayapisv1.Namespace("test")),
						Name:      "g2",
					},
				}},
				Hostnames: []gatewayapisv1.Hostname{"bla.example.com"},
			},
		}
		routes = []*gatewayapisv1.HTTPRoute{route1, route2, route3}

		log                = logger.NewContext("", "TestEnv")
		emptyMap           = map[string]source.CertInfo{}
		standardObjectMeta = metav1.ObjectMeta{
			Namespace: "test",
			Name:      "g1",
			Annotations: map[string]string{
				ctrlsource.AnnotationPurposeKey: ctrlsource.AnnotationPurposeValueManaged,
			},
		}
	)

	var _ = DescribeTable("GetCertsInfo",
		func(gateway *gatewayapisv1.Gateway, httpRoutes []*gatewayapisv1.HTTPRoute, expectedMap map[string]source.CertInfo) {
			handler, err := newGatewaySourceWithRouteLister(&testRouteLister{routes: httpRoutes}, newState())
			Expect(err).To(Succeed())

			actual, err := handler.GetCertsInfo(log, gateway)
			if err != nil {
				if expectedMap != nil {
					Fail("unexpected error: " + err.Error())
				}
				return
			}
			if expectedMap == nil {
				Fail("expected error, but got CertsInfo")
				return
			}
			expectedInfo := source.NewCertsInfo()
			expectedInfo.Certs = expectedMap
			Expect(*actual).To(Equal(*expectedInfo))
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
						Hostname: ptr.To(gatewayapisv1.Hostname("a.example.com")),
					},
				},
			},
		}, nil, emptyMap),
		Entry("should have empty info if multiple certificate refs are provided", &gatewayapisv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: gatewayapisv1.GatewaySpec{
				Listeners: []gatewayapisv1.Listener{
					{
						Hostname: ptr.To(gatewayapisv1.Hostname("a.example.com")),
						TLS: &gatewayapisv1.GatewayTLSConfig{
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
						Hostname: ptr.To(gatewayapisv1.Hostname("a.example.com")),
						TLS: &gatewayapisv1.GatewayTLSConfig{
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
						Hostname: ptr.To(gatewayapisv1.Hostname("a.example.com")),
						Protocol: gatewayapisv1.HTTPProtocolType,
						TLS: &gatewayapisv1.GatewayTLSConfig{
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
						Hostname: ptr.To(gatewayapisv1.Hostname("a.example.com")),
						Protocol: gatewayapisv1.HTTPSProtocolType,
						TLS: &gatewayapisv1.GatewayTLSConfig{
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
						Hostname: ptr.To(gatewayapisv1.Hostname("a.example.com")),
						Protocol: gatewayapisv1.HTTPSProtocolType,
						TLS: &gatewayapisv1.GatewayTLSConfig{
							CertificateRefs: []gatewayapisv1.SecretObjectReference{
								{Namespace: ptr.To(gatewayapisv1.Namespace("ns1")), Name: "foo"},
							},
						},
					},
				},
			},
		}, nil, singleCertInfo("foo", ptr.To("ns1"), "a.example.com")),
		Entry("should have single certsInfo info if single certificate is provided and protocol is TLSProtocolType", &gatewayapisv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: gatewayapisv1.GatewaySpec{
				Listeners: []gatewayapisv1.Listener{
					{
						Hostname: ptr.To(gatewayapisv1.Hostname("a.example.com")),
						Protocol: gatewayapisv1.TLSProtocolType,
						TLS: &gatewayapisv1.GatewayTLSConfig{
							CertificateRefs: []gatewayapisv1.SecretObjectReference{
								{Name: "foo"},
							},
						},
					},
				},
			},
		}, nil, singleCertInfo("foo", nil, "a.example.com")),
		Entry("gateway with multiple listeners", &gatewayapisv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: gatewayapisv1.GatewaySpec{
				Listeners: []gatewayapisv1.Listener{
					{
						Hostname: ptr.To(gatewayapisv1.Hostname("a.example.com")),
						Protocol: gatewayapisv1.HTTPSProtocolType,
						TLS: &gatewayapisv1.GatewayTLSConfig{
							CertificateRefs: []gatewayapisv1.SecretObjectReference{
								{Name: "foo1"},
							},
						},
					},
					{
						Hostname: ptr.To(gatewayapisv1.Hostname("b.example.com")),
						Protocol: gatewayapisv1.HTTPSProtocolType,
						TLS: &gatewayapisv1.GatewayTLSConfig{
							CertificateRefs: []gatewayapisv1.SecretObjectReference{
								{Name: "foo2"},
							},
						},
					},
				},
			},
		}, nil, toMap(
			makeCertInfo("foo1", nil, "a.example.com"),
			makeCertInfo("foo2", nil, "b.example.com"),
		)),
		Entry("assigned gateway to service with wildcard hostname and HTTPRoutes", &gatewayapisv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: gatewayapisv1.GatewaySpec{
				Listeners: []gatewayapisv1.Listener{
					{
						Hostname: ptr.To(gatewayapisv1.Hostname("*.example.com")),
						Protocol: gatewayapisv1.HTTPSProtocolType,
						TLS: &gatewayapisv1.GatewayTLSConfig{
							CertificateRefs: []gatewayapisv1.SecretObjectReference{
								{Name: "foo"},
							},
						},
					},
				},
			},
		}, routes, singleCertInfo("foo", nil, "*.example.com")),
		Entry("assigned gateway to service with hostname and HTTPRoutes", &gatewayapisv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: gatewayapisv1.GatewaySpec{
				Listeners: []gatewayapisv1.Listener{
					{
						Hostname: ptr.To(gatewayapisv1.Hostname("b.example.com")),
						Protocol: gatewayapisv1.HTTPSProtocolType,
						TLS: &gatewayapisv1.GatewayTLSConfig{
							CertificateRefs: []gatewayapisv1.SecretObjectReference{
								{Name: "foo"},
							},
						},
					},
				},
			},
		}, routes, singleCertInfo("foo", nil, "b.example.com", "foo.example.com", "bar.example.com")),
		Entry("hosts in cert annotation override all hosts", &gatewayapisv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test",
				Name:      "g1",
				Annotations: map[string]string{
					source.AnnotCertDNSNames:        "a.example.com,c.example.com",
					ctrlsource.AnnotationPurposeKey: ctrlsource.AnnotationPurposeValueManaged,
				},
			},
			Spec: gatewayapisv1.GatewaySpec{
				Listeners: []gatewayapisv1.Listener{
					{
						Hostname: ptr.To(gatewayapisv1.Hostname("b.example.com")),
						Protocol: gatewayapisv1.HTTPSProtocolType,
						TLS: &gatewayapisv1.GatewayTLSConfig{
							CertificateRefs: []gatewayapisv1.SecretObjectReference{
								{Name: "foo"},
							},
						},
					},
				},
			},
		}, routes, singleCertInfo("foo", nil, "a.example.com", "c.example.com")),
		Entry("check various cert annotations", &gatewayapisv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test",
				Name:      "g1",
				Annotations: map[string]string{
					ctrlsource.AnnotationPurposeKey:   ctrlsource.AnnotationPurposeValueManaged,
					source.AnnotPreferredChain:        "chain2",
					source.AnnotCommonName:            "a.example.com",
					source.AnnotCertDNSNames:          "c.example.com,d.example.com",
					source.AnnotIssuer:                "test-issuer",
					source.AnnotPrivateKeyAlgorithm:   "ECDSA",
					source.AnnotPrivateKeySize:        "384",
					source.AnnotCertSecretLabels:      "a=b, c=bar42",
					source.AnnotDNSRecordProviderType: "dummy-type",
					source.AnnotDNSRecordSecretRef:    "dummy",
				},
			},
			Spec: gatewayapisv1.GatewaySpec{
				Listeners: []gatewayapisv1.Listener{
					{
						Hostname: ptr.To(gatewayapisv1.Hostname("b.example.com")),
						Protocol: gatewayapisv1.HTTPSProtocolType,
						TLS: &gatewayapisv1.GatewayTLSConfig{
							CertificateRefs: []gatewayapisv1.SecretObjectReference{
								{Name: "foo"},
							},
						},
					},
				},
			},
		}, routes, toMap(modifyCertInfo(makeCertInfo("foo", nil, "a.example.com", "c.example.com", "d.example.com"), func(info source.CertInfo) source.CertInfo {
			info.PreferredChain = "chain2"
			info.PrivateKeyAlgorithm = "ECDSA"
			info.PrivateKeySize = 384
			info.IssuerName = ptr.To("test-issuer")
			info.SecretLabels = map[string]string{"a": "b", "c": "bar42"}
			info.Annotations = map[string]string{
				source.AnnotDNSRecordProviderType: "dummy-type",
				source.AnnotDNSRecordSecretRef:    "dummy",
			}
			return info
		}))))
})

type testRouteLister struct {
	routes []*gatewayapisv1.HTTPRoute
}

var _ httpRouteLister = &testRouteLister{}

func (t testRouteLister) ListHTTPRoutes(gateway *resources.ObjectName) ([]resources.ObjectData, error) {
	var filtered []resources.ObjectData
	for _, r := range t.routes {
		for _, ref := range r.Spec.ParentRefs {
			if gateway == nil ||
				(ref.Namespace == nil || string(*ref.Namespace) == (*gateway).Namespace()) && string(ref.Name) == (*gateway).Name() {
				filtered = append(filtered, r)
			}
		}
	}
	return filtered, nil
}

func singleCertInfo(secretName string, ns *string, names ...string) map[string]source.CertInfo {
	info := makeCertInfo(secretName, ns, names...)
	return toMap(info)
}

func toMap(infos ...source.CertInfo) map[string]source.CertInfo {
	result := map[string]source.CertInfo{}
	for _, info := range infos {
		key := info.SecretName
		if info.SecretNamespace != nil {
			key = *info.SecretNamespace + "/" + info.SecretName
		}
		result[key] = info
	}
	return result
}

func makeCertInfo(secretName string, ns *string, names ...string) source.CertInfo {
	return source.CertInfo{
		SecretName:      secretName,
		SecretNamespace: ns,
		Domains:         names,
	}
}

func modifyCertInfo(info source.CertInfo, modifier func(info source.CertInfo) source.CertInfo) source.CertInfo {
	return modifier(info)
}

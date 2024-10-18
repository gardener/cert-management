// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package istio

import (
	"fmt"

	"github.com/gardener/cert-management/pkg/cert/source"
	ctrlsource "github.com/gardener/cert-management/pkg/controller/source"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apinetworkingv1 "istio.io/api/networking/v1"
	istionetworkingv1 "istio.io/client-go/pkg/apis/networking/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var _ = Describe("Istio Gateway Handler", func() {
	var (
		service1 = &corev1.LoadBalancerStatus{
			Ingress: []corev1.LoadBalancerIngress{
				{IP: "1.2.3.4"},
			},
		}
		service2 = &corev1.LoadBalancerStatus{
			Ingress: []corev1.LoadBalancerIngress{
				{Hostname: "lb-example.com"},
			},
		}
		ingress1 = &corev1.LoadBalancerStatus{
			Ingress: []corev1.LoadBalancerIngress{
				{Hostname: "ingress-lb.example.com"},
			},
		}
		defaultSources = map[string]*corev1.LoadBalancerStatus{
			"app=istio-ingressgateway,name=service1": service1,
			"app=istio-ingressgateway,name=service2": service2,
			"ingress=foo/bar":                        ingress1,
		}
		selectorService1   = map[string]string{"app": "istio-ingressgateway", "name": "service1"}
		selectorService2   = map[string]string{"app": "istio-ingressgateway", "name": "service2"}
		log                = logger.NewContext("", "TestEnv")
		emptyMap           = map[types.NamespacedName]source.CertInfo{}
		standardObjectMeta = metav1.ObjectMeta{
			Namespace: "test",
			Name:      "g1",
			Annotations: map[string]string{
				ctrlsource.AnnotationPurposeKey: ctrlsource.AnnotationPurposeValueManaged,
			},
		}
		standardObjectMetaWithSecretNamespace = metav1.ObjectMeta{
			Namespace: "test",
			Name:      "g1",
			Annotations: map[string]string{
				ctrlsource.AnnotationPurposeKey: ctrlsource.AnnotationPurposeValueManaged,
				source.AnnotSecretNamespace:     "test-ns",
			},
		}
		vsvc1 = &istionetworkingv1.VirtualService{
			Spec: apinetworkingv1.VirtualService{
				Gateways: []string{"test/g1"},
				Hosts:    []string{"foo.example.com", "bar.example.com"},
			},
		}
		vsvc2 = &istionetworkingv1.VirtualService{
			Spec: apinetworkingv1.VirtualService{
				Gateways: []string{"test/g1"},
				Hosts:    []string{"foo.example.com"},
			},
		}
		vsvc3 = &istionetworkingv1.VirtualService{
			Spec: apinetworkingv1.VirtualService{
				Gateways: []string{"test/g2"},
				Hosts:    []string{"bla.example.com"},
			},
		}
		allVirtualServices = []*istionetworkingv1.VirtualService{vsvc1, vsvc2, vsvc3}
		otherSecretName    = types.NamespacedName{
			Namespace: "test-ns",
			Name:      "mysecret",
		}
	)

	var _ = DescribeTable("GetCertsInfo",
		func(sources map[string]*corev1.LoadBalancerStatus, gateway *istionetworkingv1.Gateway, virtualServices []*istionetworkingv1.VirtualService, expectedMap map[types.NamespacedName]source.CertInfo) {
			lister := &testResourceLister{sources: sources, virtualServices: virtualServices}
			state := newState()
			handler, err := newGatewaySourceWithResourceLister(lister, state)
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
		Entry("unmanaged gateway", defaultSources, &istionetworkingv1.Gateway{
			Spec: apinetworkingv1.Gateway{
				Servers: []*apinetworkingv1.Server{
					{Hosts: []string{"a.example.com"}},
				},
				Selector: selectorService1,
			},
		}, nil, emptyMap),
		Entry("without TLS settings", defaultSources, &istionetworkingv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: apinetworkingv1.Gateway{
				Servers: []*apinetworkingv1.Server{
					{Hosts: []string{"a.example.com"}},
				},
				Selector: selectorService1,
			},
		}, nil, emptyMap),
		Entry("with passthrough", defaultSources, &istionetworkingv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: apinetworkingv1.Gateway{
				Servers: []*apinetworkingv1.Server{
					{
						Hosts: []string{"a.example.com"},
						Tls:   &apinetworkingv1.ServerTLSSettings{Mode: apinetworkingv1.ServerTLSSettings_PASSTHROUGH},
					},
				},
				Selector: selectorService1,
			},
		}, nil, emptyMap),
		Entry("assigned gateway to service", defaultSources, &istionetworkingv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: apinetworkingv1.Gateway{
				Servers: []*apinetworkingv1.Server{
					{
						Hosts: []string{"a.example.com"},
						Tls: &apinetworkingv1.ServerTLSSettings{
							Mode:           apinetworkingv1.ServerTLSSettings_SIMPLE,
							CredentialName: "mysecret",
						},
					},
				},
				Selector: selectorService1,
			},
		}, nil, singleCertInfo("mysecret", "a.example.com")),
		Entry("assigned gateway to service with secret namespace overwrite", defaultSources, &istionetworkingv1.Gateway{
			ObjectMeta: standardObjectMetaWithSecretNamespace,
			Spec: apinetworkingv1.Gateway{
				Servers: []*apinetworkingv1.Server{
					{
						Hosts: []string{"a.example.com"},
						Tls: &apinetworkingv1.ServerTLSSettings{
							Mode:           apinetworkingv1.ServerTLSSettings_SIMPLE,
							CredentialName: "mysecret",
						},
					},
				},
				Selector: selectorService1,
			},
		}, nil, map[types.NamespacedName]source.CertInfo{otherSecretName: {
			SecretName: otherSecretName,
			Domains:    []string{"a.example.com"},
		}}),
		Entry("assigned gateway to service with virtual services", defaultSources, &istionetworkingv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: apinetworkingv1.Gateway{
				Servers: []*apinetworkingv1.Server{
					{
						Hosts: []string{"a.example.com"},
						Tls: &apinetworkingv1.ServerTLSSettings{
							Mode:           apinetworkingv1.ServerTLSSettings_SIMPLE,
							CredentialName: "mysecret",
						},
					},
				},
				Selector: selectorService1,
			},
		}, allVirtualServices, singleCertInfo("mysecret", "a.example.com", "foo.example.com", "bar.example.com")),
		Entry("assigned gateway to service with hostname", defaultSources, &istionetworkingv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: apinetworkingv1.Gateway{
				Servers: []*apinetworkingv1.Server{
					{
						Hosts: []string{"ns1/b.example.com"},
						Tls: &apinetworkingv1.ServerTLSSettings{
							Mode:           apinetworkingv1.ServerTLSSettings_SIMPLE,
							CredentialName: "mysecret",
						},
					},
				},
				Selector: selectorService2,
			},
		}, nil, singleCertInfo("mysecret", "b.example.com")),
		Entry("ignore '*' hosts", defaultSources, &istionetworkingv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: apinetworkingv1.Gateway{
				Servers: []*apinetworkingv1.Server{
					{
						Hosts: []string{"*", "ns2/c.example2.com"},
						Tls: &apinetworkingv1.ServerTLSSettings{
							Mode:           apinetworkingv1.ServerTLSSettings_SIMPLE,
							CredentialName: "mysecret",
						},
					},
				},
				Selector: selectorService2,
			},
		}, nil, singleCertInfo("mysecret", "c.example2.com")),
		Entry("ignore dns.gardener.cloud/dnsnames annotation", defaultSources, &istionetworkingv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test",
				Name:      "g1",
				Annotations: map[string]string{
					source.AnnotDnsnames:            "a.example.com,c.example.com",
					ctrlsource.AnnotationPurposeKey: ctrlsource.AnnotationPurposeValueManaged,
				},
			},
			Spec: apinetworkingv1.Gateway{
				Servers: []*apinetworkingv1.Server{
					{
						Hosts: []string{"*/a.example.com", "ns2/c.example.com", "d.example.com"},
						Tls: &apinetworkingv1.ServerTLSSettings{
							Mode:           apinetworkingv1.ServerTLSSettings_SIMPLE,
							CredentialName: "mysecret",
						},
					},
				},
				Selector: selectorService2,
			},
		}, nil, singleCertInfo("mysecret", "a.example.com", "c.example.com", "d.example.com")),
		Entry("selective hosts", defaultSources, &istionetworkingv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test",
				Name:      "g1",
				Annotations: map[string]string{
					source.AnnotCertDNSNames:        "a.example.com,c.example.com",
					ctrlsource.AnnotationPurposeKey: ctrlsource.AnnotationPurposeValueManaged,
				},
			},
			Spec: apinetworkingv1.Gateway{
				Servers: []*apinetworkingv1.Server{
					{
						Hosts: []string{"*/a.example.com", "ns2/c.example.com", "d.example.com"},
						Tls: &apinetworkingv1.ServerTLSSettings{
							Mode:           apinetworkingv1.ServerTLSSettings_SIMPLE,
							CredentialName: "mysecret",
						},
					},
				},
				Selector: selectorService2,
			},
		}, nil, singleCertInfo("mysecret", "a.example.com", "c.example.com")),
		Entry("explicit common name", defaultSources, &istionetworkingv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test",
				Name:      "g1",
				Annotations: map[string]string{
					source.AnnotCommonName:          "cn.example.com",
					ctrlsource.AnnotationPurposeKey: ctrlsource.AnnotationPurposeValueManaged,
				},
			},
			Spec: apinetworkingv1.Gateway{
				Servers: []*apinetworkingv1.Server{
					{
						Hosts: []string{"*/a.example.com", "ns2/c.example.com", "d.example.com"},
						Tls: &apinetworkingv1.ServerTLSSettings{
							Mode:           apinetworkingv1.ServerTLSSettings_SIMPLE,
							CredentialName: "mysecret",
						},
					},
				},
				Selector: selectorService2,
			},
		}, nil, singleCertInfo("mysecret", "cn.example.com", "a.example.com", "c.example.com", "d.example.com")),
		Entry("gateway with virtual services", defaultSources, &istionetworkingv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: apinetworkingv1.Gateway{
				Servers: []*apinetworkingv1.Server{
					{
						Hosts: []string{"*.example.com"},
						Tls: &apinetworkingv1.ServerTLSSettings{
							Mode:           apinetworkingv1.ServerTLSSettings_SIMPLE,
							CredentialName: "mysecret",
						},
					},
				},
				Selector: selectorService2,
			},
		}, allVirtualServices, singleCertInfo("mysecret", "*.example.com")),
		Entry("gateway with wildcard host and virtual services", defaultSources, &istionetworkingv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: apinetworkingv1.Gateway{
				Servers: []*apinetworkingv1.Server{
					{
						Hosts: []string{"*"},
						Tls: &apinetworkingv1.ServerTLSSettings{
							Mode:           apinetworkingv1.ServerTLSSettings_SIMPLE,
							CredentialName: "mysecret",
						},
					},
				},
				Selector: selectorService2,
			},
		}, allVirtualServices, singleCertInfo("mysecret", "foo.example.com", "bar.example.com")),
	)
})

type testResourceLister struct {
	sources         map[string]*corev1.LoadBalancerStatus
	virtualServices []*istionetworkingv1.VirtualService
}

var _ resourceLister = &testResourceLister{}

func (t *testResourceLister) ListServices(selectors map[string]string) ([]resources.ObjectData, error) {
	ls, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchLabels: selectors})
	Expect(err).To(Succeed())

	lbStatus := t.sources[ls.String()]
	if lbStatus == nil {
		return nil, nil
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "foo",
			Name:      "svc",
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer,
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: *lbStatus,
			Conditions:   nil,
		},
	}

	return []resources.ObjectData{svc}, nil
}

func (t *testResourceLister) GetIngress(name resources.ObjectName) (resources.ObjectData, error) {
	lbStatus := t.sources["ingress="+name.String()]
	if lbStatus == nil {
		return nil, fmt.Errorf("not found")
	}

	ilbstatus := networkingv1.IngressLoadBalancerStatus{}
	for _, item := range lbStatus.Ingress {
		ilbstatus.Ingress = append(ilbstatus.Ingress, networkingv1.IngressLoadBalancerIngress{
			IP:       item.IP,
			Hostname: item.Hostname,
		})
	}
	ingress := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: name.Namespace(),
			Name:      name.Name(),
		},
		Status: networkingv1.IngressStatus{
			LoadBalancer: ilbstatus,
		},
	}
	return &ingress, nil
}

func (t *testResourceLister) ListVirtualServices(gateway *resources.ObjectName) ([]resources.ObjectData, error) {
	var list []resources.ObjectData
	name := ""
	if gateway != nil {
		name = (*gateway).Namespace() + "/" + (*gateway).Name()
	}
outer:
	for _, vsvc := range t.virtualServices {
		for _, gw := range vsvc.Spec.Gateways {
			if name == "" || gw == name {
				list = append(list, vsvc)
				continue outer
			}
		}
	}
	return list, nil
}

func singleCertInfo(secretName string, names ...string) map[types.NamespacedName]source.CertInfo {
	info := makeCertInfo(secretName, names...)
	return toMap(info)
}

func toMap(infos ...source.CertInfo) map[types.NamespacedName]source.CertInfo {
	result := map[types.NamespacedName]source.CertInfo{}
	for _, info := range infos {
		result[info.SecretName] = info
	}
	return result
}

func makeCertInfo(secretName string, names ...string) source.CertInfo {
	return source.CertInfo{
		SecretName: types.NamespacedName{Namespace: "test", Name: secretName},
		Domains:    names,
	}
}

// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package istio_gateway

import (
	"context"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apinetworkingv1 "istio.io/api/networking/v1"
	istionetworkingv1 "istio.io/client-go/pkg/apis/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	certmanclient "github.com/gardener/cert-management/pkg/certman2/client"
	"github.com/gardener/cert-management/pkg/certman2/controller/source"
)

var _ = Describe("Reconciler", func() {
	var (
		ctx                = context.Background()
		log                = logr.Discard()
		emptyMap           = source.CertInputMap{}
		standardObjectMeta = metav1.ObjectMeta{
			Namespace: "test",
			Name:      "g1",
			Annotations: map[string]string{
				source.AnnotationPurposeKey: source.AnnotationPurposeValueManaged,
			},
		}
		fakeClient client.Client
		reconciler *Reconciler

		allVirtualServices = func() []*istionetworkingv1.VirtualService {
			vsvc1 := &istionetworkingv1.VirtualService{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test",
					Name:      "vsvc1",
				},
				Spec: apinetworkingv1.VirtualService{
					Gateways: []string{"test/g1"},
					Hosts:    []string{"foo.example.com", "bar.example.com"},
				},
			}
			vsvc2 := &istionetworkingv1.VirtualService{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test",
					Name:      "vsvc2",
				},
				Spec: apinetworkingv1.VirtualService{
					Gateways: []string{"test/g1"},
					Hosts:    []string{"foo.example.com"},
				},
			}
			vsvc3 := &istionetworkingv1.VirtualService{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test",
					Name:      "vsvc3",
				},
				Spec: apinetworkingv1.VirtualService{
					Gateways: []string{"test/g2"},
					Hosts:    []string{"bla.example.com"},
				},
			}
			return []*istionetworkingv1.VirtualService{vsvc1, vsvc2, vsvc3}
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
		func(gateway *istionetworkingv1.Gateway, virtualServices []*istionetworkingv1.VirtualService, expectedMap source.CertInputMap) {
			for _, vs := range virtualServices {
				Expect(fakeClient.Create(ctx, vs)).NotTo(HaveOccurred(), vs.Name)
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
				actualMap = source.CertInputMap{}
			}
			Expect(actualMap).To(Equal(expectedMap))
		},
		Entry("unmanaged gateway", &istionetworkingv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: apinetworkingv1.Gateway{
				Servers: []*apinetworkingv1.Server{
					{Hosts: []string{"a.example.com"}},
				},
			},
		}, nil, emptyMap),
		Entry("without TLS settings", &istionetworkingv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: apinetworkingv1.Gateway{
				Servers: []*apinetworkingv1.Server{
					{Hosts: []string{"a.example.com"}},
				},
			},
		}, nil, emptyMap),
		Entry("with passthrough", &istionetworkingv1.Gateway{
			ObjectMeta: standardObjectMeta,
			Spec: apinetworkingv1.Gateway{
				Servers: []*apinetworkingv1.Server{
					{
						Hosts: []string{"a.example.com"},
						Tls:   &apinetworkingv1.ServerTLSSettings{Mode: apinetworkingv1.ServerTLSSettings_PASSTHROUGH},
					},
				},
			},
		}, nil, emptyMap),
		Entry("assigned gateway to service", &istionetworkingv1.Gateway{
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
			},
		}, nil, singleCertInput("mysecret", "a.example.com")),
		Entry("assigned gateway to service with virtual services", &istionetworkingv1.Gateway{
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
			},
		}, allVirtualServices(), singleCertInput("mysecret", "a.example.com", "foo.example.com", "bar.example.com")),
		Entry("assigned gateway to service with hostname", &istionetworkingv1.Gateway{
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
			},
		}, nil, singleCertInput("mysecret", "b.example.com")),
		Entry("ignore '*' hosts", &istionetworkingv1.Gateway{
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
			},
		}, nil, singleCertInput("mysecret", "c.example2.com")),
		Entry("ignore dns.gardener.cloud/dnsnames annotation", &istionetworkingv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test",
				Name:      "g1",
				Annotations: map[string]string{
					source.AnnotDnsnames:        "a.example.com,c.example.com",
					source.AnnotationPurposeKey: source.AnnotationPurposeValueManaged,
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
			},
		}, nil, singleCertInput("mysecret", "a.example.com", "c.example.com", "d.example.com")),
		Entry("selective hosts", &istionetworkingv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test",
				Name:      "g1",
				Annotations: map[string]string{
					source.AnnotCertDNSNames:    "a.example.com,c.example.com",
					source.AnnotationPurposeKey: source.AnnotationPurposeValueManaged,
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
			},
		}, nil, singleCertInput("mysecret", "a.example.com", "c.example.com")),
		Entry("explicit common name", &istionetworkingv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test",
				Name:      "g1",
				Annotations: map[string]string{
					source.AnnotCommonName:      "cn.example.com",
					source.AnnotationPurposeKey: source.AnnotationPurposeValueManaged,
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
			},
		}, nil, singleCertInput("mysecret", "cn.example.com", "a.example.com", "c.example.com", "d.example.com")),
		Entry("gateway with virtual services", &istionetworkingv1.Gateway{
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
			},
		}, allVirtualServices(), singleCertInput("mysecret", "*.example.com")),
		Entry("gateway with wildcard host and virtual services", &istionetworkingv1.Gateway{
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
			},
		}, allVirtualServices(), singleCertInput("mysecret", "foo.example.com", "bar.example.com")),
	)
})

func singleCertInput(secretName string, names ...string) source.CertInputMap {
	info := makeCertInput(secretName, names...)
	return toMap(info)
}

func toMap(inputs ...source.CertInput) source.CertInputMap {
	result := source.CertInputMap{}
	for _, input := range inputs {
		result[input.SecretObjectKey] = input
	}
	return result
}

func makeCertInput(secretName string, names ...string) source.CertInput {
	return source.CertInput{
		SecretObjectKey: client.ObjectKey{Namespace: "test", Name: secretName},
		Domains:         names,
	}
}

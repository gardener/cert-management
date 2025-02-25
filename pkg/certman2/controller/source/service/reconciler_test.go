// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	certmanv1alpha1 "github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
	certmanclient "github.com/gardener/cert-management/pkg/certman2/client"
	"github.com/gardener/cert-management/pkg/certman2/controller/source/common"
	. "github.com/gardener/cert-management/pkg/certman2/controller/source/service"
	"github.com/gardener/cert-management/pkg/certman2/testutils"
)

const longDomain = "a-long-long-domain-name-with-more-than-63-characters.example.com"

var _ = Describe("Reconciler", func() {
	var (
		ctx          = context.Background()
		fakeClient   client.Client
		fakeRecorder *record.FakeRecorder
		svc          *corev1.Service
		cert         *certmanv1alpha1.Certificate
		reconciler   *Reconciler

		testWithoutCreation = func(spec *certmanv1alpha1.CertificateSpec, expectedErrorMessage ...string) {
			req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}}
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
					if owner.Name == svc.Name {
						items = append(items, item)
					}
				}
			}
			if spec == nil {
				Expect(items).To(BeEmpty())
				return
			}
			Expect(items).To(HaveLen(1))
			cert := items[0]
			Expect(cert.Namespace).To(Equal("test"))
			Expect(cert.Name).To(ContainSubstring("foo-service-"))
			Expect(cert.OwnerReferences).To(HaveLen(1))
			Expect(cert.OwnerReferences[0]).To(MatchFields(IgnoreExtras, Fields{
				"APIVersion": Equal("v1"),
				"Kind":       Equal("Service"),
				"Name":       Equal("foo"),
				"Controller": PointTo(BeTrue()),
			}))
			Expect(cert.Spec).To(Equal(*spec))
		}

		test = func(spec *certmanv1alpha1.CertificateSpec, expectedErrorMessage ...string) {
			Expect(fakeClient.Create(ctx, svc)).NotTo(HaveOccurred())
			testWithoutCreation(spec, expectedErrorMessage...)
		}
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().WithScheme(certmanclient.ClusterScheme).Build()
		reconciler = &Reconciler{}
		reconciler.Client = fakeClient
		reconciler.Complete()
		fakeRecorder = record.NewFakeRecorder(32)
		reconciler.Recorder = fakeRecorder
		svc = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo",
				Namespace: "test",
				Annotations: map[string]string{
					common.AnnotSecretname: "foo-secret",
					common.AnnotDnsnames:   "foo.example.com",
				},
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeLoadBalancer,
			},
		}
		cert = &certmanv1alpha1.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo-service-1",
				Namespace: "test",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         "v1",
						Kind:               "Service",
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
		It("should create certificate object for service of type load balancer", func() {
			test(&certmanv1alpha1.CertificateSpec{
				CommonName: ptr.To("foo.example.com"),
				SecretRef:  &corev1.SecretReference{Name: "foo-secret", Namespace: "test"},
			})
			testutils.AssertEvents(fakeRecorder.Events, "Normal CertificateCreated ")
		})

		It("should drop certificate object if secretname not set", func() {
			Expect(fakeClient.Create(ctx, cert)).NotTo(HaveOccurred())
			delete(svc.Annotations, common.AnnotSecretname)
			test(nil)
			testutils.AssertEvents(fakeRecorder.Events, "Normal CertificateDeleted ")
		})

		It("should fail if no domain name set", func() {
			delete(svc.Annotations, common.AnnotDnsnames)
			test(nil, "no valid domain name annotations found")
			testutils.AssertEvents(fakeRecorder.Events, "Warning Invalid ")
		})

		It("should fail if dnsnames are set to '*'", func() {
			svc.Annotations[common.AnnotDnsnames] = "*"
			test(nil, "no valid domain name annotations found")
			testutils.AssertEvents(fakeRecorder.Events, "Warning Invalid ")
		})

		It("should succeed if '*' dnsnames is overwritten by common name", func() {
			svc.Annotations[common.AnnotDnsnames] = "*"
			svc.Annotations[common.AnnotCommonName] = "foo.example.com"
			test(&certmanv1alpha1.CertificateSpec{
				CommonName: ptr.To("foo.example.com"),
				SecretRef:  &corev1.SecretReference{Name: "foo-secret", Namespace: "test"},
			})
			testutils.AssertEvents(fakeRecorder.Events, "Normal CertificateCreated")
		})

		It("should create correct certificate object if domain name with cert annotation", func() {
			svc.Annotations[common.AnnotCertDNSNames] = "foo.cert.example.com,foo-alt.cert.example.com"
			test(&certmanv1alpha1.CertificateSpec{
				CommonName: ptr.To("foo.cert.example.com"),
				DNSNames:   []string{"foo-alt.cert.example.com"},
				SecretRef:  &corev1.SecretReference{Name: "foo-secret", Namespace: "test"},
			})
		})

		It("should create correct certificate object if common name with cert annotation", func() {
			svc.Annotations[common.AnnotCommonName] = "foo.cert.example.com"
			svc.Annotations[common.AnnotCertDNSNames] = "foo-alt.cert.example.com"
			test(&certmanv1alpha1.CertificateSpec{
				CommonName: ptr.To("foo.cert.example.com"),
				DNSNames:   []string{"foo-alt.cert.example.com"},
				SecretRef:  &corev1.SecretReference{Name: "foo-secret", Namespace: "test"},
			})
		})

		It("should create correct certificate object with overwritten secret namespace", func() {
			svc.Annotations[common.AnnotSecretNamespace] = "other"
			test(&certmanv1alpha1.CertificateSpec{
				CommonName: ptr.To("foo.example.com"),
				SecretRef:  &corev1.SecretReference{Name: "foo-secret", Namespace: "other"},
			})
		})

		It("should update certificate object for service of type load balancer with additional fields", func() {
			svc.Annotations[common.AnnotDnsnames] = fmt.Sprintf("foo1.%s,foo2.%s", longDomain, longDomain)
			svc.Annotations[common.AnnotClass] = common.DefaultClass
			svc.Annotations[common.AnnotIssuer] = "my-ns/my-issuer"
			svc.Annotations[common.AnnotFollowCNAME] = "true"
			svc.Annotations[common.AnnotCertSecretLabels] = "key1=value1,key2=value2"
			svc.Annotations[common.AnnotDNSRecordProviderType] = "local"
			svc.Annotations[common.AnnotDNSRecordSecretRef] = "my-provider-ns/my-provider-secret"
			svc.Annotations[common.AnnotPreferredChain] = "my-chain"
			svc.Annotations[common.AnnotPrivateKeyAlgorithm] = "ECDSA"
			svc.Annotations[common.AnnotPrivateKeySize] = "384"
			cert.Spec.SecretName = ptr.To("foo-secret")
			Expect(fakeClient.Create(ctx, cert)).NotTo(HaveOccurred())
			test(&certmanv1alpha1.CertificateSpec{
				CommonName:   nil,
				DNSNames:     []string{"foo1." + longDomain, "foo2." + longDomain},
				SecretRef:    &corev1.SecretReference{Name: "foo-secret", Namespace: "test"},
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
			Expect(cert.Annotations).To(Equal(map[string]string{common.AnnotClass: "gardencert", common.AnnotDNSRecordProviderType: "local", common.AnnotDNSRecordSecretRef: "my-provider-ns/my-provider-secret"}))
			testutils.AssertEvents(fakeRecorder.Events, "Normal CertificateUpdated ")
		})

		It("should keep certificate object and drop obsolete ones", func() {
			cert2 := cert.DeepCopy()
			cert3 := cert.DeepCopy()
			Expect(fakeClient.Create(ctx, cert)).NotTo(HaveOccurred())
			cert2.Name = "foo-service-2"
			cert2.Spec = certmanv1alpha1.CertificateSpec{
				CommonName: ptr.To("foo.example.com"),
				SecretRef:  &corev1.SecretReference{Name: "foo-secret", Namespace: "test"},
			}
			Expect(fakeClient.Create(ctx, cert2)).NotTo(HaveOccurred())
			cert3.Name = "other-service"
			cert3.OwnerReferences[0].Name = "other"
			cert3.ResourceVersion = ""
			Expect(fakeClient.Create(ctx, cert3)).NotTo(HaveOccurred())
			test(&certmanv1alpha1.CertificateSpec{
				CommonName: ptr.To("foo.example.com"),
				SecretRef:  &corev1.SecretReference{Name: "foo-secret", Namespace: "test"},
			})
			Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(cert2), &certmanv1alpha1.Certificate{})).NotTo(HaveOccurred())
			Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(cert3), &certmanv1alpha1.Certificate{})).NotTo(HaveOccurred())
			testutils.AssertEvents(fakeRecorder.Events, "Normal CertificateDeleted ")
		})

		It("should delete certificate object if type is changed", func() {
			test(&certmanv1alpha1.CertificateSpec{
				CommonName: ptr.To("foo.example.com"),
				SecretRef:  &corev1.SecretReference{Name: "foo-secret", Namespace: "test"},
			})
			svc.Spec.Type = corev1.ServiceTypeClusterIP
			Expect(fakeClient.Update(ctx, svc)).NotTo(HaveOccurred())
			testWithoutCreation(nil)
			testutils.AssertEvents(fakeRecorder.Events, "Normal CertificateCreated ", "Normal CertificateDeleted ")
		})
	})
})

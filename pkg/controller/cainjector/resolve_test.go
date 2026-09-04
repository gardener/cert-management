/*
 * SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package cainjector

import (
	"github.com/gardener/controller-manager-library/pkg/resources"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
)

// fakeGetter is a lightweight objectGetter that serves objects from an in-memory map keyed by
// "<namespace>/<name>", copying the stored object into the passed target.
type fakeGetter struct {
	resource string
	objects  map[string]resources.ObjectData
}

func newFakeGetter(resource string) *fakeGetter {
	return &fakeGetter{resource: resource, objects: map[string]resources.ObjectData{}}
}

func (f *fakeGetter) put(obj resources.ObjectData) {
	f.objects[obj.GetNamespace()+"/"+obj.GetName()] = obj
}

func (f *fakeGetter) GetInto(name resources.ObjectName, target resources.ObjectData) (resources.Object, error) {
	key := name.Namespace() + "/" + name.Name()
	stored, ok := f.objects[key]
	if !ok {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: f.resource}, name.Name())
	}
	switch t := target.(type) {
	case *api.Certificate:
		*t = *stored.(*api.Certificate)
	case *corev1.Secret:
		*t = *stored.(*corev1.Secret)
	default:
		Fail("unsupported target type in fakeGetter")
	}
	return nil, nil
}

func newTestInjector(certs, secrets *fakeGetter) *injector {
	return &injector{
		certResources:   certs,
		secretResources: secrets,
		certRefs:        map[string]resources.ClusterObjectKeySet{},
		secretRefs:      map[string]resources.ClusterObjectKeySet{},
	}
}

func certificate(namespace, name, secretName string) *api.Certificate {
	return &api.Certificate{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       api.CertificateSpec{SecretName: &secretName},
	}
}

func secret(namespace, name string, ca []byte, annotations map[string]string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Annotations: annotations},
		Data:       map[string][]byte{caCrtKey: ca},
	}
}

var _ = Describe("resolveCA", func() {
	const namespace = "test"
	var (
		caBundle = []byte("-----BEGIN CERTIFICATE-----\nMY-CA\n-----END CERTIFICATE-----")
		certs    *fakeGetter
		secrets  *fakeGetter
		inj      *injector
	)

	BeforeEach(func() {
		certs = newFakeGetter("certificates")
		secrets = newFakeGetter("secrets")
		inj = newTestInjector(certs, secrets)
	})

	Context("no injection annotation", func() {
		It("returns no CA and no requeue", func() {
			ca, requeue, err := inj.resolveCA(namespace, map[string]string{"unrelated": "x"})
			Expect(err).NotTo(HaveOccurred())
			Expect(requeue).To(BeFalse())
			Expect(ca).To(BeNil())
		})
	})

	Context("inject-ca-from (certificate)", func() {
		It("resolves the CA from the certificate's secret", func() {
			certs.put(certificate(namespace, "cert1", "secret1"))
			secrets.put(secret(namespace, "secret1", caBundle, nil))

			ca, requeue, err := inj.resolveCA(namespace, map[string]string{AnnotationInjectCAFrom: namespace + "/cert1"})
			Expect(err).NotTo(HaveOccurred())
			Expect(requeue).To(BeFalse())
			Expect(ca).To(Equal(caBundle))
		})

		It("does not require the allow-direct-injection guard on the certificate's secret", func() {
			certs.put(certificate(namespace, "cert1", "secret1"))
			secrets.put(secret(namespace, "secret1", caBundle, nil)) // no guard annotation

			ca, _, err := inj.resolveCA(namespace, map[string]string{AnnotationInjectCAFrom: namespace + "/cert1"})
			Expect(err).NotTo(HaveOccurred())
			Expect(ca).To(Equal(caBundle))
		})

		It("requeues when the certificate does not exist", func() {
			ca, requeue, err := inj.resolveCA(namespace, map[string]string{AnnotationInjectCAFrom: namespace + "/missing"})
			Expect(err).NotTo(HaveOccurred())
			Expect(requeue).To(BeTrue())
			Expect(ca).To(BeNil())
		})

		It("requeues when the certificate's secret does not exist yet", func() {
			certs.put(certificate(namespace, "cert1", "secret1"))
			ca, requeue, err := inj.resolveCA(namespace, map[string]string{AnnotationInjectCAFrom: namespace + "/cert1"})
			Expect(err).NotTo(HaveOccurred())
			Expect(requeue).To(BeTrue())
			Expect(ca).To(BeNil())
		})

		It("requeues when ca.crt is empty", func() {
			certs.put(certificate(namespace, "cert1", "secret1"))
			secrets.put(secret(namespace, "secret1", nil, nil))
			ca, requeue, err := inj.resolveCA(namespace, map[string]string{AnnotationInjectCAFrom: namespace + "/cert1"})
			Expect(err).NotTo(HaveOccurred())
			Expect(requeue).To(BeTrue())
			Expect(ca).To(BeNil())
		})
	})

	Context("inject-ca-from-secret (direct)", func() {
		It("resolves the CA when the allow-direct-injection guard is set", func() {
			secrets.put(secret(namespace, "secret1", caBundle, map[string]string{AnnotationAllowDirectInjection: "true"}))
			ca, requeue, err := inj.resolveCA(namespace, map[string]string{AnnotationInjectCAFromSecret: namespace + "/secret1"})
			Expect(err).NotTo(HaveOccurred())
			Expect(requeue).To(BeFalse())
			Expect(ca).To(Equal(caBundle))
		})

		It("skips injection (no CA, no requeue) when the guard is missing", func() {
			secrets.put(secret(namespace, "secret1", caBundle, nil))
			ca, requeue, err := inj.resolveCA(namespace, map[string]string{AnnotationInjectCAFromSecret: namespace + "/secret1"})
			Expect(err).NotTo(HaveOccurred())
			Expect(requeue).To(BeFalse())
			Expect(ca).To(BeNil())
		})

		It("skips injection when the guard is not exactly \"true\"", func() {
			secrets.put(secret(namespace, "secret1", caBundle, map[string]string{AnnotationAllowDirectInjection: "yes"}))
			ca, _, err := inj.resolveCA(namespace, map[string]string{AnnotationInjectCAFromSecret: namespace + "/secret1"})
			Expect(err).NotTo(HaveOccurred())
			Expect(ca).To(BeNil())
		})

		It("requeues when the secret does not exist", func() {
			ca, requeue, err := inj.resolveCA(namespace, map[string]string{AnnotationInjectCAFromSecret: namespace + "/missing"})
			Expect(err).NotTo(HaveOccurred())
			Expect(requeue).To(BeTrue())
			Expect(ca).To(BeNil())
		})
	})
})

var _ = Describe("splitNamespacedName", func() {
	It("parses <namespace>/<name>", func() {
		ns, name, err := splitNamespacedName("default", "foo/bar")
		Expect(err).NotTo(HaveOccurred())
		Expect(ns).To(Equal("foo"))
		Expect(name).To(Equal("bar"))
	})

	It("falls back to the default namespace for a bare name", func() {
		ns, name, err := splitNamespacedName("default", "bar")
		Expect(err).NotTo(HaveOccurred())
		Expect(ns).To(Equal("default"))
		Expect(name).To(Equal("bar"))
	})

	It("rejects malformed references", func() {
		_, _, err := splitNamespacedName("default", "a/b/c")
		Expect(err).To(HaveOccurred())
		_, _, err = splitNamespacedName("default", "")
		Expect(err).To(HaveOccurred())
	})
})

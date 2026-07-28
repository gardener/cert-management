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
	"k8s.io/apimachinery/pkg/runtime/schema"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
)

var _ = Describe("reverse index", func() {
	const (
		clusterID = "source"
		namespace = "test"
	)
	var (
		inj              *injector
		validatingWHKind = schema.GroupKind{Group: "admissionregistration.k8s.io", Kind: "ValidatingWebhookConfiguration"}
		injectableKey    = resources.NewClusterKey(clusterID, validatingWHKind, namespace, "webhook1")
		certKey          = resources.NewClusterKey(clusterID, api.Kind(api.CertificateKind), namespace, "cert1")
		secretKey        = resources.NewClusterKey(clusterID, schema.GroupKind{Kind: "Secret"}, namespace, "secret1")
	)

	BeforeEach(func() {
		inj = newTestInjector(newFakeGetter("certificates"), newFakeGetter("secrets"))
	})

	It("indexes an inject-ca-from certificate reference and finds the referer", func() {
		inj.trackRefs(injectableKey, namespace, map[string]string{AnnotationInjectCAFrom: namespace + "/cert1"})
		Expect(inj.referers(certKey)).To(ConsistOf(injectableKey))
		Expect(inj.referers(secretKey)).To(BeEmpty())
	})

	It("indexes an inject-ca-from-secret reference and finds the referer", func() {
		inj.trackRefs(injectableKey, namespace, map[string]string{AnnotationInjectCAFromSecret: namespace + "/secret1"})
		Expect(inj.referers(secretKey)).To(ConsistOf(injectableKey))
		Expect(inj.referers(certKey)).To(BeEmpty())
	})

	It("removes stale references when the annotation changes", func() {
		inj.trackRefs(injectableKey, namespace, map[string]string{AnnotationInjectCAFrom: namespace + "/cert1"})
		Expect(inj.referers(certKey)).To(ConsistOf(injectableKey))

		// switch to a direct secret reference
		inj.trackRefs(injectableKey, namespace, map[string]string{AnnotationInjectCAFromSecret: namespace + "/secret1"})
		Expect(inj.referers(certKey)).To(BeEmpty())
		Expect(inj.referers(secretKey)).To(ConsistOf(injectableKey))
	})

	It("forgets references when the injectable is deleted", func() {
		inj.trackRefs(injectableKey, namespace, map[string]string{AnnotationInjectCAFrom: namespace + "/cert1"})
		inj.forgetRefs(injectableKey)
		Expect(inj.referers(certKey)).To(BeEmpty())
	})

	It("tracks multiple injectables referencing the same certificate", func() {
		other := resources.NewClusterKey(clusterID, validatingWHKind, namespace, "webhook2")
		inj.trackRefs(injectableKey, namespace, map[string]string{AnnotationInjectCAFrom: namespace + "/cert1"})
		inj.trackRefs(other, namespace, map[string]string{AnnotationInjectCAFrom: namespace + "/cert1"})
		Expect(inj.referers(certKey)).To(ConsistOf(injectableKey, other))
	})
})

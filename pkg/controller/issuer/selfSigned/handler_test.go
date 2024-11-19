package selfSigned_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/controller/issuer/selfSigned"
)

var _ = Describe("Handler", func() {
	h, _ := selfSigned.NewSelfSignedIssuerHandler(nil)

	Context("#CanReconcile", func() {
		It("should return false if issuer is nil", func() {
			Expect(h.CanReconcile(nil)).To(BeFalse())
		})

		It("should return false if issuer type is unset", func() {
			issuer := &api.Issuer{}
			Expect(h.CanReconcile(issuer)).To(BeFalse())
		})

		It("should return false if issuer type is not self-signed", func() {
			issuer := &api.Issuer{Spec: api.IssuerSpec{ACME: &api.ACMESpec{}}}
			Expect(h.CanReconcile(issuer)).To(BeFalse())
		})

		It("should return true if issuer type is self-signed", func() {
			issuer := &api.Issuer{Spec: api.IssuerSpec{SelfSigned: &api.SelfSignedSpec{}}}
			Expect(h.CanReconcile(issuer)).To(BeTrue())
		})
	})
})

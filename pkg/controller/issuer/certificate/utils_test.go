package certificate

import (
	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Utils", func() {
	Context("#hasMultipleIssuerTypes", func() {
		var issuer *api.Issuer

		BeforeEach(func() {
			issuer = &api.Issuer{}
		})

		It("should return false if no issuer type is specified", func() {
			Expect(hasMultipleIssuerTypes(issuer)).To(BeFalse())
		})

		It("should return false if only one issuer type is specified", func() {
			issuer.Spec.ACME = &api.ACMESpec{}
			Expect(hasMultipleIssuerTypes(issuer)).To(BeFalse())
		})

		It("should return true if multiple issuer types are specified", func() {
			issuer.Spec.ACME = &api.ACMESpec{}
			issuer.Spec.SelfSigned = &api.SelfSignedSpec{}
			Expect(hasMultipleIssuerTypes(issuer)).To(BeTrue())
		})
	})
})

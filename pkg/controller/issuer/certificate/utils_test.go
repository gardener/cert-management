// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package certificate

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
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

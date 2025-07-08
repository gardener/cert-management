// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package certificate

import (
	"net"
	"net/url"

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

	Context("#ValidateEmailAddresses", func() {
		It("should return no error when passing no email addresses", func() {
			err := ValidateEmailAddresses(nil)
			Expect(err).ToNot(HaveOccurred())
		})

		It("should return no error when passing a single, valid email address", func() {
			err := ValidateEmailAddresses([]string{"foo@example.com"})
			Expect(err).ToNot(HaveOccurred())
		})

		It("should return no error when passing multiple valid email addresses", func() {
			err := ValidateEmailAddresses([]string{"foo@example.com", "bar@example.com"})
			Expect(err).ToNot(HaveOccurred())
		})

		It("should return an error when passing a single, invalid email address", func() {
			err := ValidateEmailAddresses([]string{"invalid-email"})
			Expect(err).To(MatchError("invalid email address: invalid-email, error: mail: missing '@' or angle-addr"))
		})

		It("should return an error when passing multiple, invalid email addresses", func() {
			err := ValidateEmailAddresses([]string{"not-this", "not-that"})
			Expect(err).To(MatchError("invalid email address: not-this, error: mail: missing '@' or angle-addr"))
		})
	})

	Context("#ParseIPAddresses", func() {
		It("should return no error when passing no IP addresses", func() {
			ips, err := ParseIPAddresses(nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(ips).To(BeNil())
		})

		It("should return a single IP address when passing a valid one", func() {
			ips, err := ParseIPAddresses([]string{"1.1.1.1"})
			Expect(err).ToNot(HaveOccurred())
			Expect(ips).To(Equal([]net.IP{net.ParseIP("1.1.1.1")}))
		})

		It("should return multiple IP addresses when passing valid ones", func() {
			ips, err := ParseIPAddresses([]string{"1.1.1.1", "1.0.0.1"})
			Expect(err).ToNot(HaveOccurred())
			Expect(ips).To(Equal([]net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("1.0.0.1")}))
		})

		It("should return an error when passing an invalid IP address", func() {
			ips, err := ParseIPAddresses([]string{"invalid-ip"})
			Expect(err).To(MatchError("invalid IP address: invalid-ip"))
			Expect(ips).To(BeNil())
		})

		It("should return an error when passing multiple invalid IP addresses", func() {
			ips, err := ParseIPAddresses([]string{"not-this", "not-that"})
			Expect(err).To(MatchError("invalid IP address: not-this"))
			Expect(ips).To(BeNil())
		})
	})

	Context("#ParseURIs", func() {
		It("should return no error when passing no URIs", func() {
			uris, err := ParseURIs(nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(uris).To(BeNil())
		})

		It("should return a single URI when passing a valid one", func() {
			uris, err := ParseURIs([]string{"https://example.com"})
			Expect(err).ToNot(HaveOccurred())
			Expect(uris).To(Equal([]*url.URL{{Scheme: "https", Host: "example.com"}}))
		})

		It("should return multiple URIs when passing valid ones", func() {
			uris, err := ParseURIs([]string{"https://example.com", "http://example.org"})
			Expect(err).ToNot(HaveOccurred())
			Expect(uris).To(Equal([]*url.URL{
				{Scheme: "https", Host: "example.com"},
				{Scheme: "http", Host: "example.org"},
			}))
		})

		It("should return an error when passing an invalid URI", func() {
			uris, err := ParseURIs([]string{":foo/bar"})
			Expect(err).To(MatchError("invalid URI: :foo/bar, error: parse \":foo/bar\": missing protocol scheme"))
			Expect(uris).To(BeNil())
		})

		It("should return an error when passing an URI without a scheme", func() {
			uris, err := ParseURIs([]string{"foo/bar"})
			Expect(err).To(MatchError("invalid URI: foo/bar, scheme is missing"))
			Expect(uris).To(BeNil())
		})

		It("should return an error when passing multiple invalid URIs", func() {
			uris, err := ParseURIs([]string{":not-this", ":not-that"})
			Expect(err).To(MatchError("invalid URI: :not-this, error: parse \":not-this\": missing protocol scheme"))
			Expect(uris).To(BeNil())
		})
	})
})

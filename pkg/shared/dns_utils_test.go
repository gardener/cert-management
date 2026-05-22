// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package shared_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/cert-management/pkg/shared"
)

var _ = Describe("DnsUtils", func() {
	DescribeTable("#PreparePrecheckNameservers / #parseNameservers",
		func(input, expected []string) {
			Expect(shared.PreparePrecheckNameservers(input)).To(Equal(expected))
		},
		Entry("should keep nameservers that already have a port",
			[]string{"1.1.1.1:53", "1.1.1.2:53"},
			[]string{"1.1.1.1:53", "1.1.1.2:53"},
		),
		Entry("should add default port 53 to nameservers without a port",
			[]string{"1.1.1.1", "1.1.1.2"},
			[]string{"1.1.1.1:53", "1.1.1.2:53"},
		),
		Entry("should handle mixed nameservers with and without port",
			[]string{"1.1.1.1", "1.1.1.2:5353"},
			[]string{"1.1.1.1:53", "1.1.1.2:5353"},
		),
		Entry("should handle IPv6 address with port",
			[]string{"[::1]:53"},
			[]string{"[::1]:53"},
		),
		Entry("should add default port to bare IPv6 address",
			[]string{"::1"},
			[]string{"[::1]:53"},
		),
	)

	DescribeTable("#MatchesWildcardAnySubdomain",
		func(host, wildcard string, expected bool) {
			Expect(shared.MatchesWildcardAnySubdomain(host, wildcard)).To(Equal(expected))
		},
		Entry("should match a single-level subdomain", "foo.gardener.cloud", "*.gardener.cloud", true),
		Entry("should match multiple levels below wildcard", "a.b.gardener.cloud", "*.gardener.cloud", true),
		Entry("should match with a deeper base domain", "foo.api.gardener.cloud", "*.api.gardener.cloud", true),
		Entry("should not match when host is not a wildcard", "docs.gardener.cloud", "docs.gardener.cloud", false),
		Entry("should not match when host is the base domain of wildcard", "gardener.cloud", "*.gardener.cloud", false),
		Entry("should not match an unrelated domain", "example.com", "*.gardener.cloud", false),
	)

	DescribeTable("#MatchesWildcardSingleSubdomain",
		func(host, wildcard string, expected bool) {
			Expect(shared.MatchesWildcardSingleSubdomain(host, wildcard)).To(Equal(expected))
		},
		Entry("should match a single-level subdomain", "foo.gardener.cloud", "*.gardener.cloud", true),
		Entry("should not match multiple levels below wildcard", "a.b.gardener.cloud", "*.gardener.cloud", false),
		Entry("should match with a deeper base domain", "foo.api.gardener.cloud", "*.api.gardener.cloud", true),
		Entry("should not match when host is not a wildcard", "docs.gardener.cloud", "docs.gardener.cloud", false),
		Entry("should not match when host is the base domain of wildcard", "gardener.cloud", "*.gardener.cloud", false),
		Entry("should not match an unrelated domain", "example.com", "*.gardener.cloud", false),
	)
})

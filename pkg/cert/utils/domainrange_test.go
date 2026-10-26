/*
 * SPDX-FileCopyrightText: Contributors to the Gardener project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package utils_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/cert-management/pkg/cert/utils"
)

var _ = Describe("DomainRange", func() {
	DescribeTable("IsInDomainRange",
		func(domain, domainRange string, wanted bool) {
			result := utils.IsInDomainRange(domain, domainRange)
			Expect(result).To(Equal(wanted))
		},
		Entry("a.b in b", "a.b", "b", true),
		Entry("A.B in b", "A.B", "b", true),
		Entry("a.b in .b", "a.b", ".b", true),
		Entry("a.b in *.B", "a.b", "*.B", true),
		Entry("a.b in a.b", "a.b", "a.b", true),
		Entry("a.b not in c.b", "a.b", "c.b", false),
		Entry("a.b not in a.b.c", "a.b", "a.b.c", false),
		Entry("a.b.c in b.c", "a.b.c", "b.c", true),
		Entry("a.xb.c not in b.c", "a.xb.c", "b.c", false),
		Entry("a.b in b.", "a.b", "b.", true),
		Entry("a.b. in b", "a.b.", "b", true),
		Entry("Empty domain range acts as wildcard", "a.b.c", "", true),
		// raw (unnormalized) range must still match: fail-open bypass
		Entry("x.internal.example.com in raw *.internal.example.com", "x.internal.example.com", "*.internal.example.com", true),
		Entry("x.internal.example.com in raw INTERNAL.example.com.", "x.internal.example.com", "INTERNAL.example.com.", true),
		// wildcard *.example.com is NOT in a narrower range like secret.example.com
		Entry("*.example.com not in secret.example.com", "*.example.com", "secret.example.com", false),
		Entry("*.example.com in example.com", "*.example.com", "example.com", true),
		Entry("*.example.com not in a.secret.example.com", "*.example.com", "a.secret.example.com", false),
	)

	DescribeTable("IsInDomainRanges",
		func(domain string, domainRanges []string, wanted bool) {
			for i, domainRange := range domainRanges {
				domainRanges[i] = utils.NormalizeDomainRange(domainRange)
			}
			result := utils.IsInDomainRanges(domain, domainRanges)
			Expect(result).To(Equal(wanted))
		},
		Entry("a.b in {b}", "a.b", []string{"b"}, true),
		Entry("a.b in {b, c}", "a.b", []string{"b", "c"}, true),
		Entry("a.b in {c, b}", "a.b", []string{"c", "b"}, true),
		Entry("a.b not in {c, d}", "a.b", []string{"c", "d"}, false),
		Entry("Nil acts as wildcard", "a.b", nil, true),
	)

	DescribeTable("BestDomainRange",
		func(domain string, domainRanges []string, wanted string) {
			for i, domainRange := range domainRanges {
				domainRanges[i] = utils.NormalizeDomainRange(domainRange)
			}
			result := utils.BestDomainRange(domain, domainRanges)
			Expect(result).To(Equal(wanted))
		},
		Entry("a.b in {b} returns b", "a.b", []string{"b"}, "b"),
		Entry("a.b in {b, c} returns b", "a.b", []string{"b", "c"}, "b"),
		Entry("a.b.c in {b.c., c} returns b.c", "a.b.c", []string{"b.c", "c"}, "b.c"),
		Entry("Nil acts as wildcard", "a.b", nil, "*"),
	)

})

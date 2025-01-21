/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package utils_test

import (
	"github.com/gardener/cert-management/pkg/cert/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("IsInDomainRange", func() {
	DescribeTable("domain range tests",
		func(domain, domainRange string, wanted bool) {
			domainRange = utils.NormalizeDomainRange(domainRange)
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
	)
})

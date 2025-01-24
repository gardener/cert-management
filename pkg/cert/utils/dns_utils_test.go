// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package utils_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/cert-management/pkg/cert/utils"
)

var _ = Describe("DnsUtils", func() {
	Describe("PreparePrecheckNameservers", func() {
		It("should return given nameservers if they are valid", func() {
			nameservers := []string{"1.1.1.1:53", "1.1.1.2:53"}
			Expect(utils.PreparePrecheckNameservers(nameservers)).To(Equal(nameservers))
		})

		It("should return given nameservers if they are valid and adds missing ports", func() {
			nameservers := []string{"1.1.1.1", "1.1.1.2"}
			nameserversExpected := []string{"1.1.1.1:53", "1.1.1.2:53"}
			Expect(utils.PreparePrecheckNameservers(nameservers)).To(Equal(nameserversExpected))
		})
	})
})

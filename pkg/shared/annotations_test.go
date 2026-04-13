// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package shared_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gardener/cert-management/pkg/shared"
)

var _ = Describe("ParseRenewBefore", func() {
	Context("when the input is empty", func() {
		It("returns nil and no error", func() {
			result, err := shared.ParseRenewBefore("")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(BeNil())
		})
	})

	Context("when the input is a valid duration", func() {
		It("parses a duration expressed in hours", func() {
			result, err := shared.ParseRenewBefore("720h")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(&metav1.Duration{Duration: 720 * time.Hour}))
		})

		It("parses the minimum allowed duration of exactly 5 minutes", func() {
			result, err := shared.ParseRenewBefore("5m")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(&metav1.Duration{Duration: 5 * time.Minute}))
		})

		It("parses a duration expressed in minutes greater than 5", func() {
			result, err := shared.ParseRenewBefore("30m")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(&metav1.Duration{Duration: 30 * time.Minute}))
		})

		It("parses a combined hours and minutes duration", func() {
			result, err := shared.ParseRenewBefore("2h30m")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(&metav1.Duration{Duration: 2*time.Hour + 30*time.Minute}))
		})

		It("parses a duration expressed in seconds that equals exactly 5 minutes", func() {
			result, err := shared.ParseRenewBefore("300s")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(&metav1.Duration{Duration: 300 * time.Second}))
		})
	})

	Context("when the input is an invalid duration string", func() {
		It("returns nil and an error for a completely invalid string", func() {
			result, err := shared.ParseRenewBefore("not-a-duration")
			Expect(result).To(BeNil())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid renew-before annotation value"))
			Expect(err.Error()).To(ContainSubstring("not-a-duration"))
		})

		It("returns nil and an error for a bare number without a unit", func() {
			result, err := shared.ParseRenewBefore("300")
			Expect(result).To(BeNil())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid renew-before annotation value"))
			Expect(err.Error()).To(ContainSubstring("300"))
		})
	})

	Context("when the duration is below the minimum of 5 minutes", func() {
		It("returns nil and an error for 4 minutes 59 seconds", func() {
			result, err := shared.ParseRenewBefore("4m59s")
			Expect(result).To(BeNil())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("must be at least 5 minutes"))
		})

		It("returns nil and an error for 1 minute", func() {
			result, err := shared.ParseRenewBefore("1m")
			Expect(result).To(BeNil())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("must be at least 5 minutes"))
		})

		It("returns nil and an error for 299 seconds", func() {
			result, err := shared.ParseRenewBefore("299s")
			Expect(result).To(BeNil())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("must be at least 5 minutes"))
		})

		It("returns nil and an error for 0s", func() {
			result, err := shared.ParseRenewBefore("0s")
			Expect(result).To(BeNil())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("must be at least 5 minutes"))
		})
	})
})

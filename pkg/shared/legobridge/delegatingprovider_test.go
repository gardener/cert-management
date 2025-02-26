// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package legobridge

import (
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/wait"
)

var _ = Describe("Delegating Provider", func() {
	Describe("retryOnUpdateEroor", func() {
		BeforeEach(func() {
			// Override the default backoff settings to speed up the tests
			backoff = wait.Backoff{
				Steps:    4,
				Duration: 10 * time.Millisecond,
				Factor:   1.1,
				Jitter:   0.1,
				Cap:      100 * time.Millisecond,
			}
		})

		It("should succeed without error", func() {
			err := retryOnUpdateError(func() error {
				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should succeed after a few retries if updateError occurs", func() {
			var i int
			err := retryOnUpdateError(func() error {
				i++
				if i < 3 {
					return &updateError{"failed"}
				}
				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should fail if some other error occurs and return the error", func() {
			var i int
			err := retryOnUpdateError(func() error {
				i++
				if i < 3 {
					return errors.New("failed")
				}
				return nil
			})
			Expect(err).To(MatchError("failed"))
		})

		It("should fail after timeout", func() {
			err := retryOnUpdateError(func() error {
				return &updateError{"failed"}
			})
			Expect(err).To(HaveOccurred())
		})
	})
})

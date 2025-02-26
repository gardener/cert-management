// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package legobridge_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/cert-management/pkg/shared/legobridge"
)

var _ = Describe("Pending", func() {
	It("should add an object to PendingCertificateRequests and remove it afterwards", func() {
		name := client.ObjectKey{Namespace: "test", Name: "test-cert"}
		pendingRequests := legobridge.NewPendingRequests()
		By("Adding the Object")
		pendingRequests.Add(name)
		Expect(pendingRequests.Contains(name)).To(BeTrue())

		By("Removing the Object")
		pendingRequests.Remove(name)
		Expect(pendingRequests.Contains(name)).To(BeFalse())
	})

	It("should add an object to PendingResults and remove it afterwards", func() {
		name := client.ObjectKey{Namespace: "test", Name: "test-cert"}
		pendingResults := legobridge.NewPendingResults()
		result := &legobridge.ObtainOutput{}

		By("Adding the Object")
		pendingResults.Add(name, result)
		Expect(pendingResults.Peek(name)).To(Equal(result))

		By("Removing the Object")
		pendingResults.Remove(name)
		Expect(pendingResults.Peek(name)).To(BeNil())
	})
})

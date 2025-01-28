package legobridge_test

import (
	"github.com/gardener/cert-management/pkg/cert/legobridge"
	"github.com/gardener/controller-manager-library/pkg/resources"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Pending", func() {
	var(
		name resources.ObjectName
	)

	BeforeEach(func() {
		name = resources.NewObjectName("test", "test-cert")
	})

	It("should add an object to PendingCertificateRequests and remove it afterwards", func() {
		pendingRequests := legobridge.NewPendingRequests()
		By("Adding the Obeject")
		pendingRequests.Add(name)
		Expect(pendingRequests.Contains(name)).To(BeTrue())

		By("Removing the Object")
		pendingRequests.Remove(name)
		Expect(pendingRequests.Contains(name)).To(BeFalse())
	})

	It("should add an object to PendingResults and remove it afterwards", func() {
		pendingResults := legobridge.NewPendingResults()
		result := &legobridge.ObtainOutput{}

		By("Adding the Obeject")
		pendingResults.Add(name, result)
		Expect(pendingResults.Peek(name)).To(Equal(result))

		By("Removing the Object")
		pendingResults.Remove(name)
		Expect(pendingResults.Peek(name)).To(BeNil())
	})
})

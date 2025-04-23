// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package certificate

import (
	"github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/shared/legobridge"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("Certificate reconcile", func() {
	Context("#isOrphanedPendingCertificate", func() {
		var (
			reconciler *Reconciler
			cert       *v1alpha1.Certificate
		)

		BeforeEach(func() {
			reconciler = &Reconciler{
				pendingRequests: legobridge.NewPendingRequests(),
				pendingResults:  legobridge.NewPendingResults(),
			}
			cert = &v1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:    "default",
					GenerateName: "cert-",
				},
			}
		})

		It("should return true for an orphaned pending certificate", func() {
			cert.Status.State = v1alpha1.StatePending
			Expect(reconciler.isOrphanedPendingCertificate(cert)).To(BeTrue())
		})

		It("should return false for a non-pending certificate", func() {
			cert.Status.State = v1alpha1.StateReady
			Expect(reconciler.isOrphanedPendingCertificate(cert)).To(BeFalse())
		})

		It("should return false when the certificate has a pending challenge", func() {
			cert.Status.State = v1alpha1.StatePending
			reconciler.pendingRequests.Add(client.ObjectKeyFromObject(cert))
			Expect(reconciler.isOrphanedPendingCertificate(cert)).To(BeFalse())
		})

		It("should return false when the certificate has a pending result", func() {
			cert.Status.State = v1alpha1.StatePending
			reconciler.pendingResults.Add(client.ObjectKeyFromObject(cert), &legobridge.ObtainOutput{})
			Expect(reconciler.isOrphanedPendingCertificate(cert)).To(BeFalse())
		})
	})
})

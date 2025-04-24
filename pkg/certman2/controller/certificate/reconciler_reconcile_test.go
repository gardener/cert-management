// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package certificate

import (
	"context"
	"github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	certmanclient "github.com/gardener/cert-management/pkg/certman2/client"
	"github.com/gardener/cert-management/pkg/shared/legobridge"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"time"
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
					Namespace: "default",
					Name:      "cert",
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

	Context("#handleOrphanedPendingCertificate", func() {
		It("should clear the last pending timestamp and reset the certificate status", func() {
			fakeClient := fakeclient.NewClientBuilder().WithScheme(certmanclient.ClusterScheme).Build()
			reconciler := &Reconciler{
				Client: fakeClient,
			}

			cert := &v1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:    "default",
					GenerateName: "cert-",
				},
				Status: v1alpha1.CertificateStatus{
					State:                v1alpha1.StatePending,
					LastPendingTimestamp: ptr.To(metav1.NewTime(time.Now())),
				},
			}
			Expect(fakeClient.Create(context.TODO(), cert)).To(Succeed())

			result, err := reconciler.handleOrphanedPendingCertificate(context.TODO(), cert)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))
			Expect(cert.Status.LastPendingTimestamp).To(BeNil())
			Expect(cert.Status.State).To(Equal(""))
		})
	})
})

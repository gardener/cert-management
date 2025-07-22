// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package certificate

import (
	"context"
	"time"

	"github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	certmanclient "github.com/gardener/cert-management/pkg/certman2/client"
	"github.com/gardener/cert-management/pkg/shared/legobridge"
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

	Context("#hasPendingChallenge", func() {
		var reconciler *Reconciler

		BeforeEach(func() {
			reconciler = &Reconciler{
				pendingRequests: legobridge.NewPendingRequests(),
			}
		})

		It("should return true if the certificate has a pending requests", func() {
			cert := &v1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "cert",
				},
			}
			reconciler.pendingRequests.Add(client.ObjectKeyFromObject(cert))
			Expect(reconciler.hasPendingChallenge(cert)).To(BeTrue())
		})

		It("should return false if the certificate does not have a pending requests", func() {
			cert := &v1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "cert",
				},
			}
			Expect(reconciler.hasPendingChallenge(cert)).To(BeFalse())
		})
	})

	Context("#hasResultPending", func() {
		var reconciler *Reconciler

		BeforeEach(func() {
			reconciler = &Reconciler{
				pendingResults: legobridge.NewPendingResults(),
			}
		})

		It("should return true if the certificate has a pending result", func() {
			cert := &v1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "cert",
				},
			}
			reconciler.pendingResults.Add(client.ObjectKeyFromObject(cert), &legobridge.ObtainOutput{})
			Expect(reconciler.hasResultPending(cert)).To(BeTrue())
		})

		It("should return false if the certificate does not have a pending results", func() {
			cert := &v1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "cert",
				},
			}
			Expect(reconciler.hasResultPending(cert)).To(BeFalse())
		})
	})

	Context("#hasReconcileAnnotation", func() {
		var reconciler *Reconciler

		BeforeEach(func() {
			reconciler = &Reconciler{}
		})

		It("should return true if the certificate has a reconcile annotation", func() {
			cert := &v1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						constants.GardenerOperationReconcile: "true",
					},
				},
			}
			Expect(reconciler.hasReconcileAnnotation(cert)).To(BeTrue())
		})

		It("should return false if the certificate does not have a reconcile annotation", func() {
			cert := &v1alpha1.Certificate{}
			Expect(reconciler.hasReconcileAnnotation(cert)).To(BeFalse())
		})
	})

	Context("#handleReconcileAnnotation", func() {
		var (
			reconciler *Reconciler
			cert       *v1alpha1.Certificate
		)

		BeforeEach(func() {
			reconciler = &Reconciler{
				Client: fakeclient.NewClientBuilder().WithScheme(certmanclient.ClusterScheme).Build(),
			}
			cert = &v1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "cert",
					Annotations: map[string]string{
						constants.GardenerOperationReconcile: "true",
					},
				},
			}
			Expect(reconciler.Client.Create(context.TODO(), cert)).To(Succeed())
		})

		It("should remove the reconcile annotation", func() {
			result, err := reconciler.handleReconcileAnnotation(context.TODO(), cert)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))
			Expect(cert.Annotations).NotTo(HaveKey(constants.GardenerOperationReconcile))

			fetchedCert := &v1alpha1.Certificate{}
			Expect(reconciler.Client.Get(context.TODO(), client.ObjectKeyFromObject(cert), fetchedCert)).To(Succeed())
			Expect(fetchedCert.Annotations).NotTo(HaveKey(constants.GardenerOperationReconcile))
		})
	})

	Context("#shouldBackoff", func() {
		var (
			reconciler *Reconciler
			cert       *v1alpha1.Certificate
		)

		BeforeEach(func() {
			reconciler = &Reconciler{}
			cert = &v1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Generation: 1,
				},
				Status: v1alpha1.CertificateStatus{
					BackOff: &v1alpha1.BackOffState{
						ObservedGeneration: 1,
						RetryAfter:         metav1.NewTime(time.Now().Add(42 * time.Hour)),
					},
				},
			}
		})

		It("should return true if the certificate has a backoff, the generation matches, and it's too early", func() {
			Expect(reconciler.shouldBackoff(cert)).To(BeTrue())
		})

		It("should return false if the certificate has no backoff", func() {
			cert.Status.BackOff = nil
			Expect(reconciler.shouldBackoff(cert)).To(BeFalse())
		})

		It("should return false if the generation does not match", func() {
			cert.Generation = 2
			cert.Status.BackOff.ObservedGeneration = 1
			Expect(reconciler.shouldBackoff(cert)).To(BeFalse())
		})

		It("should return false if it's time to retry", func() {
			cert.Status.BackOff.RetryAfter = metav1.NewTime(time.Now().Add(-42 * time.Hour))
			Expect(reconciler.shouldBackoff(cert)).To(BeFalse())
		})
	})

	Context("#handleBackoff", func() {
		var (
			reconciler *Reconciler
			cert       *v1alpha1.Certificate
		)

		BeforeEach(func() {
			reconciler = &Reconciler{}
			cert = &v1alpha1.Certificate{
				Status: v1alpha1.CertificateStatus{
					BackOff: &v1alpha1.BackOffState{},
				},
			}
		})

		It("should return requeue after the appropriate time", func() {
			cert.Status.BackOff.RetryAfter = metav1.NewTime(time.Now().Add(42 * time.Hour))
			result := reconciler.handleBackoff(cert)
			Expect(result.RequeueAfter).To(BeNumerically(">", 41*time.Hour))
		})

		It("should requeue in 1 second if retry after is close or in the past", func() {
			cert.Status.BackOff.RetryAfter = metav1.NewTime(time.Now().Add(-42 * time.Hour))
			result := reconciler.handleBackoff(cert)
			Expect(result.RequeueAfter).To(BeNumerically("==", 1*time.Second))
		})
	})
})

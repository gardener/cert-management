// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package certificate

import (
	"context"
	"github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	certmanclient "github.com/gardener/cert-management/pkg/certman2/client"
	"github.com/gardener/cert-management/pkg/shared/legobridge"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"time"
)

var _ = Describe("#Reconcile", func() {
	var (
		reconciler *Reconciler
		fakeClient client.Client
		ctx        context.Context
		cert       *v1alpha1.Certificate
		request    reconcile.Request
	)

	BeforeEach(func() {
		ctx = context.TODO()
		fakeClient = fakeclient.NewClientBuilder().WithScheme(certmanclient.ClusterScheme).Build()
		reconciler = &Reconciler{
			Client:          fakeClient,
			pendingRequests: legobridge.NewPendingRequests(),
			pendingResults:  legobridge.NewPendingResults(),
		}
		cert = &v1alpha1.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   "default",
				Name:        "cert",
				Annotations: map[string]string{},
			},
			Status: v1alpha1.CertificateStatus{
				Message: ptr.To(""),
			},
		}
		request = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cert)}

		Expect(fakeClient.Create(ctx, cert)).To(Succeed())
	})

	It("should reconcile successfully", func() {
		result, err := reconciler.Reconcile(ctx, request)
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(reconcile.Result{}))
	})

	It("should handle an orphaned pending certificate", func() {
		cert.Status.LastPendingTimestamp = &metav1.Time{Time: time.Now()}
		cert.Status.State = v1alpha1.StatePending
		Expect(fakeClient.Update(ctx, cert)).To(Succeed())

		result, err := reconciler.Reconcile(ctx, request)
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(reconcile.Result{}))

		Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(cert), cert)).To(Succeed())
		Expect(cert.Status.LastPendingTimestamp).To(BeNil())
		Expect(cert.Status.State).To(BeEmpty())
	})

	It("should handle the reconcile annotation", func() {
		cert.Annotations[constants.GardenerOperationReconcile] = "true"
		Expect(fakeClient.Update(ctx, cert)).To(Succeed())

		result, err := reconciler.Reconcile(ctx, request)
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(reconcile.Result{}))

		Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(cert), cert)).To(Succeed())
		Expect(cert.Annotations).NotTo(HaveKey(constants.GardenerOperationReconcile))
	})

	It("should backoff when required", func() {
		cert.Generation = 1
		cert.Status.BackOff = &v1alpha1.BackOffState{
			ObservedGeneration: cert.Generation,
			RetryAfter:         metav1.NewTime(time.Now().Add(42 * time.Hour)),
		}
		Expect(fakeClient.Update(ctx, cert)).To(Succeed())

		result, err := reconciler.Reconcile(ctx, request)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter).To(BeNumerically(">", 41*time.Hour))
	})
})

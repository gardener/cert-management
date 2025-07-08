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
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

var _ = Describe("Certificate controller predicates", func() {
	Context("#PendingCertificateRequestPredicate", func() {
		var (
			evt             event.TypedCreateEvent[client.Object]
			pendingRequests *legobridge.PendingCertificateRequests
			predicateFunc   predicate.Predicate
		)

		BeforeEach(func() {
			evt = event.TypedCreateEvent[client.Object]{
				Object: &v1alpha1.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "default",
						Name:      "cert0",
					},
				},
			}
			pendingRequests = legobridge.NewPendingRequests()
			predicateFunc = PendingCertificateRequestPredicate(pendingRequests)
		})

		It("should filter out objects with pending requests", func() {
			pendingRequests.Add(client.ObjectKey{Namespace: "default", Name: "cert0"})
			Expect(predicateFunc.Create(evt)).To(BeFalse())
		})

		It("should allow objects without pending requests", func() {
			Expect(predicateFunc.Create(evt)).To(BeTrue())
		})

		It("should allow objects after pending requests are cleared", func() {
			pendingRequests.Add(client.ObjectKey{Namespace: "default", Name: "cert0"})
			Expect(predicateFunc.Create(evt)).To(BeFalse())
			pendingRequests.Remove(client.ObjectKey{Namespace: "default", Name: "cert0"})
			Expect(predicateFunc.Create(evt)).To(BeTrue())
		})
	})
})

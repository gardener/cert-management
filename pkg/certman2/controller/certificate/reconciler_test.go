// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package certificate

import (
	certmanclient "github.com/gardener/cert-management/pkg/certman2/client"
	"github.com/gardener/cert-management/pkg/shared/legobridge"
	. "github.com/onsi/ginkgo/v2"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("#Reconcile", func() {
	var (
		ctx        context.Context
		reconciler *Reconciler
	)

	BeforeEach(func() {
		ctx = context.TODO()
		reconciler = &Reconciler{
			Client: fakeclient.NewClientBuilder().WithScheme(certmanclient.ClusterScheme).Build(),
		}
	})

	It("should return an error if it can't retrieve the certificate", func() {
		Expect(reconciler.Reconcile())
	})
})

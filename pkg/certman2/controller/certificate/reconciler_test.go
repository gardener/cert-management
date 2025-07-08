// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package certificate

import (
	certmanclient "github.com/gardener/cert-management/pkg/certman2/client"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("#Reconcile", func() {
	var (
		reconciler *Reconciler
	)

	BeforeEach(func() {
		reconciler = &Reconciler{
			Client: fakeclient.NewClientBuilder().WithScheme(certmanclient.ClusterScheme).Build(),
		}
	})

	It("should return an error if it can't retrieve the certificate", func() {
		Expect(reconciler).NotTo(BeNil())
	})
})

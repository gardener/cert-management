// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package certificate

import (
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/gardener/cert-management/pkg/certman2/controller"
	"github.com/gardener/cert-management/pkg/shared/legobridge"
)

// PendingCertificateRequestPredicate returns a predicate that filters objects if they have a pending certificate request.
func PendingCertificateRequestPredicate(pendingRequests *legobridge.PendingCertificateRequests) predicate.Predicate {
	return controller.FilterPredicate(func(obj client.Object) bool {
		return !pendingRequests.Contains(client.ObjectKeyFromObject(obj))
	})
}

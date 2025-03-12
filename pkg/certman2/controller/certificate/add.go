// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package certificate

import (
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	certcontroller "github.com/gardener/cert-management/pkg/certman2/controller"
)

// ControllerName is the name of this controller.
const ControllerName = "certificate"

// AddToManager adds Reconciler to the given manager.
func (r *Reconciler) AddToManager(mgr manager.Manager) error {
	r.Client = mgr.GetClient()
	if r.Clock == nil {
		r.Clock = clock.RealClock{}
	}
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorderFor(ControllerName + "-controller")
	}

	return builder.
		ControllerManagedBy(mgr).
		Named(ControllerName).
		For(
			&v1alpha1.Certificate{},
			builder.WithPredicates(
				certcontroller.CertClassPredicate(r.Config.Class),
			),
		).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
		}).
		Complete(r)
}

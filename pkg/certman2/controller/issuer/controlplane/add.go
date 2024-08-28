/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package controlplane

import (
	"github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/certman2/controller/issuer/acme"
	"github.com/gardener/cert-management/pkg/certman2/controller/issuer/ca"
	"github.com/gardener/cert-management/pkg/certman2/core"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// ControllerName is the name of this controller.
const ControllerName = "issuer-controlplane"

// AddToManager adds Reconciler to the given manager.
func (r *Reconciler) AddToManager(mgr manager.Manager, controlPlaneCluster cluster.Cluster) error {
	r.Client = controlPlaneCluster.GetClient()
	if r.Clock == nil {
		r.Clock = clock.RealClock{}
	}
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorderFor(ControllerName + "-controller")
	}

	support, err := core.NewHandlerSupport(
		r.Config.Controllers.Issuer.DefaultIssuerName,
		r.Config.Controllers.Issuer.Namespace,
		r.Config.Controllers.Issuer.DefaultRequestsPerDayQuota)
	if err != nil {
		return err
	}

	caIssuerHandler, err := ca.NewCAIssuerHandler(r.Client, support, true)
	if err != nil {
		return err
	}
	r.handlers = []core.IssuerHandler{caIssuerHandler}

	acmeIssuerHandler, err := acme.NewACMEIssuerHandler(r.Client, support, true)
	if err != nil {
		return err
	}
	r.handlers = append(r.handlers, acmeIssuerHandler)

	return builder.
		ControllerManagedBy(mgr).
		Named(ControllerName).
		WatchesRawSource(
			source.Kind(controlPlaneCluster.GetCache(), &v1alpha1.Issuer{}),
			&handler.EnqueueRequestForObject{},
			builder.WithPredicates(predicate.NewPredicateFuncs(func(obj client.Object) bool {
				return obj.GetNamespace() == r.Config.Controllers.Issuer.Namespace
			})),
		).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
		}).
		Complete(r)
}

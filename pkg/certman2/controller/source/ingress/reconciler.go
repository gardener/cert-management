// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/cert-management/pkg/certman2/controller/source/common"
)

// Reconciler is a reconciler for provided Certificate resources.
type Reconciler struct {
	common.ReconcilerBase
}

// Complete implements the option completer.
func (r *Reconciler) Complete() {
	r.GVK = schema.GroupVersionKind{Group: "networking.k8s.io", Version: "v1", Kind: "Ingress"}
}

// Reconcile reconciles Service resources.
func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := logf.FromContext(ctx).WithName(ControllerName)

	ingress := &networkingv1.Ingress{}
	if err := r.Client.Get(ctx, req.NamespacedName, ingress); err != nil {
		if apierrors.IsNotFound(err) {
			log.V(1).Info("Object is gone, stop reconciling")
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("error retrieving object from store: %w", err)
	}

	if ingress.Annotations[common.AnnotationPurposeKey] != common.AnnotationPurposeValueManaged {
		return r.DoDelete(ctx, log, ingress)
	} else {
		return r.reconcile(ctx, log, ingress)
	}
}

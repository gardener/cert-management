// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package certificate

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
)

func (r *Reconciler) reconcile(
	ctx context.Context,
	log logr.Logger,
	landscape *v1alpha1.Certificate,
) (
	reconcile.Result,
	error,
) {
	log.Info("reconcile certificate")
	_ = ctx
	_ = landscape
	return reconcile.Result{}, fmt.Errorf("not yet supported")
}

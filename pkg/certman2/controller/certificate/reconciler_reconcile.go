// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package certificate

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
)

func (r *Reconciler) reconcile(
	ctx context.Context,
	log logr.Logger,
	cert *v1alpha1.Certificate,
) (
	reconcile.Result,
	error,
) {
	log.Info("reconcile cert")

	if r.isOrphanedPendingCertificate(cert) {
		return r.handleOrphanedPendingCertificate(ctx, cert)
	}

	return reconcile.Result{}, fmt.Errorf("not yet supported")
}

func (r *Reconciler) isOrphanedPendingCertificate(cert *v1alpha1.Certificate) bool {
	return cert.Status.State == v1alpha1.StatePending && !r.hasPendingChallenge(cert) && !r.hasResultPending(cert)
}

// handleOrphanedPendingCertificate cleans up invalid orphaned pending state unfinished from former controller instance, resets status to trigger a retry.
func (r *Reconciler) handleOrphanedPendingCertificate(ctx context.Context, cert *v1alpha1.Certificate) (reconcile.Result, error) {
	cert.Status.LastPendingTimestamp = nil
	err := r.Client.Update(ctx, cert)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to update certificate status: %w", err)
	}
	return reconcile.Result{}, nil
}

func (r *Reconciler) hasPendingChallenge(_ *v1alpha1.Certificate) bool {
	// TODO
	return false
}

func (r *Reconciler) hasResultPending(_ *v1alpha1.Certificate) bool {
	// TODO
	return false
}

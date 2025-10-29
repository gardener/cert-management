// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package certificate

import (
	"context"
	"fmt"
	"time"

	"github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
	log.Info("reconcile certificate")

	if r.isOrphanedPendingCertificate(cert) {
		log.Info("orphaned pending certificate detected")
		return r.handleOrphanedPendingCertificate(ctx, cert)
	}

	if r.hasReconcileAnnotation(cert) {
		if r.shouldBackoff(cert) {
			log.Info("reconcile annotation found, clearing backoff and reconciling again")
			return r.clearBackoff(ctx, cert)
		}
		log.Info("reconcile annotation found, removing it and reconciling again")
		return r.handleReconcileAnnotation(ctx, cert)
	}

	if r.shouldBackoff(cert) {
		log.Info("backoff triggered")
		return r.handleBackoff(cert), nil
	}

	return reconcile.Result{}, nil
}

func (r *Reconciler) isOrphanedPendingCertificate(cert *v1alpha1.Certificate) bool {
	return cert.Status.State == v1alpha1.StatePending && !r.hasPendingChallenge(cert) && !r.hasResultPending(cert)
}

// handleOrphanedPendingCertificate cleans up invalid orphaned pending state unfinished from former controller instance, resets status to trigger a retry.
func (r *Reconciler) handleOrphanedPendingCertificate(ctx context.Context, cert *v1alpha1.Certificate) (reconcile.Result, error) {
	cert.Status.LastPendingTimestamp = nil
	cert.Status.State = ""
	err := r.Client.Update(ctx, cert)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to update certificate status: %w", err)
	}
	return reconcile.Result{}, nil
}

func (r *Reconciler) hasPendingChallenge(cert *v1alpha1.Certificate) bool {
	return r.pendingRequests.Contains(client.ObjectKeyFromObject(cert))
}

func (r *Reconciler) hasResultPending(cert *v1alpha1.Certificate) bool {
	return r.pendingResults.Peek(client.ObjectKeyFromObject(cert)) != nil
}

func (r *Reconciler) hasReconcileAnnotation(cert *v1alpha1.Certificate) bool {
	_, ok := cert.Annotations[constants.GardenerOperationReconcile]
	return ok
}

func (r *Reconciler) handleReconcileAnnotation(ctx context.Context, cert *v1alpha1.Certificate) (reconcile.Result, error) {
	patch := client.MergeFrom(cert.DeepCopy())
	delete(cert.Annotations, constants.GardenerOperationReconcile)
	if err := r.Client.Patch(ctx, cert, patch); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to remove reconcile annotation: %w", err)
	}
	return reconcile.Result{}, nil
}

func (r *Reconciler) shouldBackoff(cert *v1alpha1.Certificate) bool {
	return cert.Status.BackOff != nil &&
		cert.Generation == cert.Status.BackOff.ObservedGeneration &&
		time.Now().Before(cert.Status.BackOff.RetryAfter.Time)
}

func (r *Reconciler) handleBackoff(cert *v1alpha1.Certificate) reconcile.Result {
	interval := time.Until(cert.Status.BackOff.RetryAfter.Time)
	minInterval := 1 * time.Second
	if interval < minInterval {
		interval = minInterval
	}
	return reconcile.Result{
		RequeueAfter: interval,
	}
}

func (r *Reconciler) clearBackoff(ctx context.Context, cert *v1alpha1.Certificate) (reconcile.Result, error) {
	patch := client.MergeFrom(cert.DeepCopy())
	cert.Status.BackOff = nil
	if err := r.Client.Status().Patch(ctx, cert, patch); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to clear backoff status: %w", err)
	}
	return reconcile.Result{}, nil
}

package service

import (
	"context"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func (r *Reconciler) delete(
	ctx context.Context,
	log logr.Logger,
	service *corev1.Service,
) (
	reconcile.Result,
	error,
) {
	log.Info("deleting service")

	ownedCerts, err := r.getExistingOwnedCertificates(ctx, service)
	if err != nil {
		return reconcile.Result{}, err
	}

	if err := r.deleteObsoleteOwnedCertificates(ctx, log, service, ownedCerts, nil); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

package certificate

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
)

func (r *Reconciler) delete(
	_ context.Context,
	log logr.Logger,
	_ *v1alpha1.Certificate,
) (
	reconcile.Result,
	error,
) {
	log.Info("deleting certificate")
	return reconcile.Result{}, fmt.Errorf("not yet supported")
}

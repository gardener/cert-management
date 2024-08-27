package issuer

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/certman2/apis/config"
	"github.com/gardener/cert-management/pkg/certman2/core"
)

// Reconciler is a reconciler for provided Issuer resources.
type Reconciler struct {
	Client   client.Client
	Clock    clock.Clock
	Recorder record.EventRecorder
	Config   config.CertManagerConfiguration

	handlers []core.IssuerHandler
}

// Reconcile reconciles Issuer resources.
func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := logf.FromContext(ctx).WithName(ControllerName)

	issuer := &v1alpha1.Issuer{}
	if err := r.Client.Get(ctx, req.NamespacedName, issuer); err != nil {
		if apierrors.IsNotFound(err) {
			log.V(1).Info("Object is gone, stop reconciling")
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("error retrieving object from store: %w", err)
	}

	for _, h := range r.handlers {
		if h.CanReconcile(issuer) {
			if issuer.DeletionTimestamp != nil {
				return h.Delete(ctx, log, issuer)
			} else {
				return h.Reconcile(ctx, log, issuer)
			}
		}
	}
	return reconcile.Result{}, fmt.Errorf("unsupported issuer spec")
}

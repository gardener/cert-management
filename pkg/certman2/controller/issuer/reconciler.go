package issuer

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/certman2/apis/config"
	installerclient "github.com/gardener/cert-management/pkg/certman2/client"
)

const finalizerName = "gardener.cloud/installer"

// Reconciler is a reconciler for provided Issuer resources.
type Reconciler struct {
	ClusterAccess   *installerclient.ClusterAccess
	Clock           clock.Clock
	IssuerNamespace string
	Recorder        record.EventRecorder
	Config          config.CertManagerConfiguration
}

// Reconcile reconciles Landscape resources.
func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := logf.FromContext(ctx).WithName(ControllerName)

	issuer := &v1alpha1.Issuer{}
	if err := r.ClusterAccess.IssuerClientSet().Client().Get(ctx, req.NamespacedName, issuer); err != nil {
		if apierrors.IsNotFound(err) {
			log.V(1).Info("Object is gone, stop reconciling")
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("error retrieving object from store: %w", err)
	}

	if issuer.DeletionTimestamp != nil {
		return r.delete(ctx, log, issuer)
	} else {
		return r.reconcile(ctx, log, issuer)
	}
}

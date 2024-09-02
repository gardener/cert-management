package gateways_crd_watchdog

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"

	"github.com/gardener/cert-management/pkg/certman2/controller/source/istio_gateway"
	"github.com/go-logr/logr"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// Reconciler watches for relevant changes of gateway custom resource definitions.
type Reconciler struct {
	Client client.Client

	CheckGatewayCRDsState CheckGatewayCRDsState
	shuttingDown          atomic.Bool
}

// Reconcile reconciles custom resource definition resources.
func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := logf.FromContext(ctx).WithName(ControllerName)

	crd := &apiextensionsv1.CustomResourceDefinition{}
	if err := r.Client.Get(ctx, req.NamespacedName, crd); err != nil {
		if apierrors.IsNotFound(err) {
			log.V(1).Info("Object is gone, stop reconciling")
			log.Info("Restarting as relevant gateway CRD was deleted")
			r.shutdown(log)
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("error retrieving object from store: %w", err)
	}

	return r.reconcile(ctx, log, crd)
}

func (r *Reconciler) reconcile(_ context.Context, log logr.Logger, crd *apiextensionsv1.CustomResourceDefinition) (reconcile.Result, error) {
	exists, ok := r.CheckGatewayCRDsState.relevantCRDDeployed[crd.Name]
	if !ok {
		return reconcile.Result{}, nil
	}
	if !exists {
		log.Info("Restarting as relevant gateway CRD was deployed")
		r.shutdown(log)
	}
	switch crd.Name {
	case istioGatewaysCRD:
		if istio_gateway.GetPreferredVersion(crd) != r.CheckGatewayCRDsState.IstioGatewayVersion() {
			log.Info("Restarting as relevant gateway CRD version has changed",
				"old", r.CheckGatewayCRDsState.IstioGatewayVersion(),
				"new", istio_gateway.GetPreferredVersion(crd))
			r.shutdown(log)
		}
	case k8nGatewaysCRD:
		// TODO
	}
	return reconcile.Result{}, nil
}

func (r *Reconciler) shutdown(log logr.Logger) {
	if !r.shuttingDown.CompareAndSwap(false, true) {
		return
	}
	log.Info("Shutting down application")
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		log.Error(err, "Error shutting down application")
	}
}

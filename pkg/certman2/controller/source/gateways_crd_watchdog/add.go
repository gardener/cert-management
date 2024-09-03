package gateways_crd_watchdog

import (
	"context"
	"fmt"

	certmanclient "github.com/gardener/cert-management/pkg/certman2/client"
	"github.com/gardener/cert-management/pkg/certman2/controller/source/istio_gateway"
	k8s_gateway "github.com/gardener/cert-management/pkg/certman2/controller/source/k8n_gateway"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// ControllerName is the name of this controller.
const ControllerName = "gateways-crd-watchdog"

const (
	istioGatewaysCRD        = "gateways.networking.istio.io"
	istioVirtualServicesCRD = "virtualservices.networking.istio.io"
	k8nGatewaysCRD          = "gateways.gateway.networking.k8s.io"
	k8nHTTPRoutesCRD        = "httproutes.gateway.networking.k8s.io"
)

var relevantCRDs = []string{
	istioGatewaysCRD,
	istioVirtualServicesCRD,
	k8nGatewaysCRD,
	k8nHTTPRoutesCRD,
}

type CheckGatewayCRDsState struct {
	relevantCRDDeployed      map[string]bool
	istioGatewayVersion      istio_gateway.Version
	kubernetesGatewayVersion k8s_gateway.Version
}

// CheckGatewayCRDs checks for relevant gateway custom resource definition deployments.
func CheckGatewayCRDs(ctx context.Context, restConfig *rest.Config) (*CheckGatewayCRDsState, error) {
	state := CheckGatewayCRDsState{
		relevantCRDDeployed: map[string]bool{},
	}
	for _, name := range relevantCRDs {
		state.relevantCRDDeployed[name] = false
	}

	c, err := client.New(restConfig, client.Options{
		Scheme: certmanclient.ClusterScheme,
	})
	if err != nil {
		return nil, err
	}
	list := &apiextensionsv1.CustomResourceDefinitionList{}
	if err := c.List(ctx, list); err != nil {
		return nil, fmt.Errorf("listing custom resource definitions failed: %w", err)
	}
	for _, crd := range list.Items {
		for _, name := range relevantCRDs {
			if crd.GetName() == name {
				state.relevantCRDDeployed[name] = true
			}
			switch name {
			case istioGatewaysCRD:
				state.istioGatewayVersion = istio_gateway.GetPreferredVersion(&crd)
			case k8nGatewaysCRD:
				state.kubernetesGatewayVersion = k8s_gateway.GetPreferredVersion(&crd)
			}
		}
	}
	return &state, nil
}

// IstioGatewayVersion returns istio gateway version to watch.
func (s *CheckGatewayCRDsState) IstioGatewayVersion() istio_gateway.Version {
	return s.istioGatewayVersion
}

// KubernetesGatewayVersion returns Kubernetes Gateway API gateway version to watch.
func (s *CheckGatewayCRDsState) KubernetesGatewayVersion() k8s_gateway.Version {
	return s.kubernetesGatewayVersion
}

// AddToManager adds Reconciler to the given manager.
func (r *Reconciler) AddToManager(mgr manager.Manager) error {
	r.Client = mgr.GetClient()

	return builder.
		ControllerManagedBy(mgr).
		Named(ControllerName).
		For(
			&apiextensionsv1.CustomResourceDefinition{},
			builder.WithPredicates(Predicate()),
		).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
			RecoverPanic:            ptr.To(false),
			NeedLeaderElection:      ptr.To(false),
		}).
		Complete(r)
}

// Predicate returns the predicate to be considered for reconciliation.
func Predicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			crd, ok := e.Object.(*apiextensionsv1.CustomResourceDefinition)
			if !ok || crd == nil {
				return false
			}
			for _, name := range relevantCRDs {
				if crd.Name == name {
					return true
				}
			}
			return false
		},

		UpdateFunc: func(e event.UpdateEvent) bool {
			crd, ok := e.ObjectNew.(*apiextensionsv1.CustomResourceDefinition)
			if !ok || crd == nil {
				return false
			}
			for _, name := range relevantCRDs {
				if crd.Name == name {
					return true
				}
			}
			return false
		},

		DeleteFunc: func(e event.DeleteEvent) bool {
			crd, ok := e.Object.(*apiextensionsv1.CustomResourceDefinition)
			if !ok || crd == nil {
				return false
			}
			for _, name := range relevantCRDs {
				if crd.Name == name {
					return true
				}
			}
			return false
		},

		GenericFunc: func(event.GenericEvent) bool { return false },
	}
}

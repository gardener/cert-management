package istio_gateway

import (
	"context"
	"fmt"
	"strings"

	istionetworkingv1 "istio.io/client-go/pkg/apis/networking/v1"
	istionetworkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	istionetworkingv1beta1 "istio.io/client-go/pkg/apis/networking/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/cert-management/pkg/certman2/controller/source"
)

// Reconciler is a reconciler for provided Certificate resources.
type Reconciler struct {
	source.ReconcilerBase

	ActiveVersion Version
}

func (r *Reconciler) Complete() {
	r.GVK = schema.GroupVersionKind{Group: "networking.istio.io", Version: string(r.ActiveVersion), Kind: "Gateway"}
}

// Reconcile reconciles Gateway resources.
func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := logf.FromContext(ctx).WithName(ControllerName)

	gateway := newGateway(r.ActiveVersion)
	if err := r.Client.Get(ctx, req.NamespacedName, gateway); err != nil {
		if apierrors.IsNotFound(err) {
			log.V(1).Info("Object is gone, stop reconciling")
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("error retrieving object from store: %w", err)
	}

	if gateway.GetAnnotations()[source.AnnotationPurposeKey] != source.AnnotationPurposeValueManaged {
		return r.DoDelete(ctx, log, gateway)
	} else {
		return r.reconcile(ctx, log, gateway)
	}
}

func extractGatewayNames(virtualService client.Object) sets.Set[client.ObjectKey] {
	gatewayNames := sets.Set[client.ObjectKey]{}
	switch data := virtualService.(type) {
	case *istionetworkingv1.VirtualService:
		for _, name := range data.Spec.Gateways {
			if key := toObjectKey(name, virtualService.GetNamespace()); key != nil {
				gatewayNames.Insert(*key)
			}
		}
	case *istionetworkingv1beta1.VirtualService:
		for _, name := range data.Spec.Gateways {
			if key := toObjectKey(name, virtualService.GetNamespace()); key != nil {
				gatewayNames.Insert(*key)
			}
		}
	case *istionetworkingv1alpha3.VirtualService:
		for _, name := range data.Spec.Gateways {
			if key := toObjectKey(name, virtualService.GetNamespace()); key != nil {
				gatewayNames.Insert(*key)
			}
		}
	}
	return gatewayNames
}

func toObjectKey(name, defaultNamespace string) *client.ObjectKey {
	parts := strings.Split(name, "/")
	switch len(parts) {
	case 1:
		return &client.ObjectKey{Namespace: defaultNamespace, Name: name}
	case 2:
		return &client.ObjectKey{Namespace: parts[0], Name: parts[1]}
	}
	return nil
}

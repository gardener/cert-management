package k8s_gateway

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayapisv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapisv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayapisv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/gardener/cert-management/pkg/certman2/controller/source"
)

const gatewayKind = "Gateway"

// Reconciler is a reconciler for provided Certificate resources.
type Reconciler struct {
	source.ReconcilerBase

	ActiveVersion Version
}

// Complete implements the option completer.
func (r *Reconciler) Complete() {
	r.GVK = schema.GroupVersionKind{Group: gatewayapisv1.GroupName, Version: string(r.ActiveVersion), Kind: gatewayKind}
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

func extractGatewayNames(route client.Object) sets.Set[client.ObjectKey] {
	gatewayNames := sets.Set[client.ObjectKey]{}
	switch data := route.(type) {
	case *gatewayapisv1.HTTPRoute:
		for _, ref := range data.Spec.ParentRefs {
			if (ref.Group == nil || string(*ref.Group) == gatewayapisv1.GroupName) &&
				(ref.Kind == nil || string(*ref.Kind) == gatewayKind) {
				namespace := data.Namespace
				if ref.Namespace != nil {
					namespace = string(*ref.Namespace)
				}
				gatewayNames.Insert(client.ObjectKey{Namespace: namespace, Name: string(ref.Name)})
			}
		}
	case *gatewayapisv1beta1.HTTPRoute:
		for _, ref := range data.Spec.ParentRefs {
			if (ref.Group == nil || string(*ref.Group) == gatewayapisv1.GroupName) &&
				(ref.Kind == nil || string(*ref.Kind) == gatewayKind) {
				namespace := data.Namespace
				if ref.Namespace != nil {
					namespace = string(*ref.Namespace)
				}
				gatewayNames.Insert(client.ObjectKey{Namespace: namespace, Name: string(ref.Name)})
			}
		}
	case *gatewayapisv1alpha2.HTTPRoute:
		for _, ref := range data.Spec.ParentRefs {
			if (ref.Group == nil || string(*ref.Group) == gatewayapisv1.GroupName) &&
				(ref.Kind == nil || string(*ref.Kind) == gatewayKind) {
				namespace := data.Namespace
				if ref.Namespace != nil {
					namespace = string(*ref.Namespace)
				}
				gatewayNames.Insert(client.ObjectKey{Namespace: namespace, Name: string(ref.Name)})
			}
		}
	}
	return gatewayNames
}

package istio_gateway

import (
	"context"
	"reflect"

	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/cert-management/pkg/certman2/controller/source"
)

// ControllerName is the name of this controller.
const ControllerName = "istio-gateway-source"

// AddToManager adds Reconciler to the given manager.
func (r *Reconciler) AddToManager(mgr manager.Manager) error {
	r.Client = mgr.GetClient()
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorderFor(ControllerName + "-controller")
	}

	r.Complete()

	return builder.
		ControllerManagedBy(mgr).
		Named(ControllerName).
		For(newGateway(r.ActiveVersion), builder.WithPredicates(Predicate(newGateway(r.ActiveVersion), r.Class))).
		Watches(newVirtualService(r.ActiveVersion), handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, virtualService client.Object) []reconcile.Request {
			var requests []reconcile.Request
			for key := range extractGatewayNames(virtualService) {
				requests = append(requests, reconcile.Request{NamespacedName: key})
			}
			return requests
		})).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
		}).
		Complete(r)
}

// Predicate returns the predicate to be considered for reconciliation.
func Predicate[T client.Object](_ T, class string) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			gateway, ok := e.Object.(T)
			if !ok || isNil(gateway) {
				return false
			}
			return isRelevant(gateway, class)
		},

		UpdateFunc: func(e event.UpdateEvent) bool {
			gatewayOld, ok := e.ObjectOld.(T)
			if !ok || isNil(gatewayOld) {
				return false
			}
			gatewayNew, ok := e.ObjectNew.(T)
			if !ok || isNil(gatewayNew) {
				return false
			}
			return isRelevant(gatewayOld, class) || isRelevant(gatewayNew, class)
		},

		DeleteFunc: func(e event.DeleteEvent) bool {
			gateway, ok := e.Object.(T)
			if !ok || isNil(gateway) {
				return false
			}
			return isRelevant(gateway, class)
		},

		GenericFunc: func(event.GenericEvent) bool { return false },
	}
}

func isRelevant(obj client.Object, class string) bool {
	if isNil(obj) {
		return false
	}

	if !source.EquivalentClass(obj.GetAnnotations()[source.AnnotClass], class) {
		return false
	}
	if obj.GetAnnotations()[source.AnnotationPurposeKey] != source.AnnotationPurposeValueManaged {
		return false
	}
	return true
}

func isNil(obj client.Object) bool {
	return obj == nil || reflect.ValueOf(obj).IsNil()
}

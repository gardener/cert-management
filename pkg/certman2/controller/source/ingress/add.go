package ingress

import (
	"github.com/gardener/cert-management/pkg/certman2/controller/source"
	networkingv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// ControllerName is the name of this controller.
const ControllerName = "ingress-source"

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
		For(
			&networkingv1.Ingress{},
			builder.WithPredicates(Predicate(r.Class)),
		).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
		}).
		Complete(r)
}

// Predicate returns the predicate to be considered for reconciliation.
func Predicate(class string) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			ingress, ok := e.Object.(*networkingv1.Ingress)
			if !ok || ingress == nil {
				return false
			}
			return isRelevant(ingress, class)
		},

		UpdateFunc: func(e event.UpdateEvent) bool {
			ingressOld, ok := e.ObjectOld.(*networkingv1.Ingress)
			if !ok || ingressOld == nil {
				return false
			}
			ingressNew, ok := e.ObjectNew.(*networkingv1.Ingress)
			if !ok || ingressNew == nil {
				return false
			}
			return isRelevant(ingressOld, class) || isRelevant(ingressNew, class)
		},

		DeleteFunc: func(e event.DeleteEvent) bool {
			ingress, ok := e.Object.(*networkingv1.Ingress)
			if !ok || ingress == nil {
				return false
			}
			return isRelevant(ingress, class)
		},

		GenericFunc: func(event.GenericEvent) bool { return false },
	}
}

func isRelevant(ingress *networkingv1.Ingress, class string) bool {
	if !source.EquivalentClass(ingress.Annotations[source.AnnotClass], class) {
		return false
	}
	if ingress.Annotations[source.AnnotationPurposeKey] != source.AnnotationPurposeValueManaged {
		return false
	}
	return true
}

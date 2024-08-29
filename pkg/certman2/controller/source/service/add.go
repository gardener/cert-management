package service

import (
	"github.com/gardener/cert-management/pkg/certman2/controller/source"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// ControllerName is the name of this controller.
const ControllerName = "service-source"

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
			&corev1.Service{},
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
			service, ok := e.Object.(*corev1.Service)
			if !ok || service == nil {
				return false
			}
			return isServiceRelevant(service, class)
		},

		UpdateFunc: func(e event.UpdateEvent) bool {
			serviceOld, ok := e.ObjectOld.(*corev1.Service)
			if !ok || serviceOld == nil {
				return false
			}
			serviceNew, ok := e.ObjectNew.(*corev1.Service)
			if !ok || serviceNew == nil {
				return false
			}
			return isServiceRelevant(serviceOld, class) || isServiceRelevant(serviceNew, class)
		},

		DeleteFunc: func(e event.DeleteEvent) bool {
			service, ok := e.Object.(*corev1.Service)
			if !ok || service == nil {
				return false
			}
			return isServiceRelevant(service, class)
		},

		GenericFunc: func(event.GenericEvent) bool { return false },
	}
}

func isServiceRelevant(svc *corev1.Service, class string) bool {
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer || !source.EquivalentClass(svc.Annotations[source.AnnotClass], class) {
		return false
	}
	if _, ok := svc.Annotations[source.AnnotSecretname]; !ok {
		return false
	}
	return true
}

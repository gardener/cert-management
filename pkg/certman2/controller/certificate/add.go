package certificate

import (
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
)

// ControllerName is the name of this controller.
const ControllerName = "certificate"

// AddToManager adds Reconciler to the given manager.
func (r *Reconciler) AddToManager(mgr manager.Manager) error {
	r.Client = mgr.GetClient()
	if r.Clock == nil {
		r.Clock = clock.RealClock{}
	}
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorderFor(ControllerName + "-controller")
	}

	return builder.
		ControllerManagedBy(mgr).
		Named(ControllerName).
		For(
			&v1alpha1.Certificate{},
			builder.WithPredicates(Predicate()), // TODO check predicate
		).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
		}).
		Complete(r)
}

// Predicate returns the predicate to be considered for the Certificate resource.
func Predicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			// TODO
			certificate, ok := e.Object.(*v1alpha1.Certificate)
			if !ok || certificate == nil {
				return false
			}
			return true
		},

		UpdateFunc: func(e event.UpdateEvent) bool {
			// TODO
			certificateOld, ok := e.ObjectOld.(*v1alpha1.Certificate)
			if !ok || certificateOld == nil {
				return false
			}
			certificateNew, ok := e.ObjectNew.(*v1alpha1.Certificate)
			if !ok || certificateNew == nil {
				return false
			}
			return true
		},

		DeleteFunc: func(e event.DeleteEvent) bool {
			// TODO
			certificate, ok := e.Object.(*v1alpha1.Certificate)
			if !ok || certificate == nil {
				return false
			}
			return true
		},
		GenericFunc: func(event.GenericEvent) bool { return false },
	}
}

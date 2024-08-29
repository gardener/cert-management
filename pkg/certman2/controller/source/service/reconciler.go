package service

import (
	"context"
	"fmt"

	certmanv1alpha1 "github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// Reconciler is a reconciler for provided Certificate resources.
type Reconciler struct {
	Client   client.Client
	Recorder record.EventRecorder
	Class    string
	gvk      schema.GroupVersionKind
}

func (r *Reconciler) Complete() {
	r.gvk = schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Service"}
}

// Reconcile reconciles Service resources.
func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := logf.FromContext(ctx).WithName(ControllerName)

	service := &corev1.Service{}
	if err := r.Client.Get(ctx, req.NamespacedName, service); err != nil {
		if apierrors.IsNotFound(err) {
			log.V(1).Info("Object is gone, stop reconciling")
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("error retrieving object from store: %w", err)
	}

	if service.DeletionTimestamp != nil || service.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return r.delete(ctx, log, service)
	} else {
		return r.reconcile(ctx, log, service)
	}
}

func (r *Reconciler) getExistingOwnedCertificates(ctx context.Context, service *corev1.Service) ([]certmanv1alpha1.Certificate, error) {
	candidates := &certmanv1alpha1.CertificateList{}
	if err := r.Client.List(ctx, candidates, client.InNamespace(service.GetNamespace())); err != nil {
		return nil, fmt.Errorf("failed to list owned certificates for service %s: %w", client.ObjectKeyFromObject(service), err)
	}

	var ownedCerts []certmanv1alpha1.Certificate
outer:
	for _, candidate := range candidates.Items {
		for _, owner := range candidate.GetOwnerReferences() {
			if owner.Name == service.Name && owner.Kind == r.gvk.Kind && owner.APIVersion == r.gvk.GroupVersion().String() {
				ownedCerts = append(ownedCerts, candidate)
				continue outer
			}
		}
	}
	return ownedCerts, nil
}

func (r *Reconciler) deleteObsoleteOwnedCertificates(
	ctx context.Context,
	log logr.Logger,
	service *corev1.Service,
	ownedCerts []certmanv1alpha1.Certificate,
	certToKeep *certmanv1alpha1.Certificate,
) error {
	for _, ownedCert := range ownedCerts {
		if certToKeep == nil || certToKeep.Name != ownedCert.Name {
			if err := r.Client.Delete(ctx, &ownedCert); client.IgnoreNotFound(err) != nil {
				return fmt.Errorf("failed to delete obsolete owned certificate %s: %w", client.ObjectKeyFromObject(&ownedCert), err)
			}
			log.Info("deleted obsolete owned certificate", "name", ownedCert.Name)
			r.Recorder.Eventf(service, corev1.EventTypeNormal, "CertificateDeleted", "Created certificate: %s", ownedCert.Name) // TODO: check former reason/message
		}
	}
	return nil
}

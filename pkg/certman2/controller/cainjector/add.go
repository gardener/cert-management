// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package cainjector

import (
	"context"
	"fmt"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	certv1alpha1 "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/certman2/apis/config"
)

const (
	controllerVWC  = "cainjector-validatingwebhookconfiguration"
	controllerMWC  = "cainjector-mutatingwebhookconfiguration"
	controllerCRD  = "cainjector-customresourcedefinition"
	controllerAPIS = "cainjector-apiservice"
)

// AddToManager registers the four ca-injector controllers against mgr.
// It is a no-op if cfg.Controllers.CAInjector.Enabled is nil or false.
func AddToManager(mgr manager.Manager, cfg config.CertManagerConfiguration) error {
	if cfg.Controllers.CAInjector.Enabled == nil || !*cfg.Controllers.CAInjector.Enabled {
		return nil
	}

	r := &Reconciler{Client: mgr.GetClient()}

	if err := addVWCController(mgr, r); err != nil {
		return fmt.Errorf("adding VWC ca-injector: %w", err)
	}
	if err := addMWCController(mgr, r); err != nil {
		return fmt.Errorf("adding MWC ca-injector: %w", err)
	}
	if err := addCRDController(mgr, r); err != nil {
		return fmt.Errorf("adding CRD ca-injector: %w", err)
	}
	if err := addAPIServiceController(mgr, r); err != nil {
		return fmt.Errorf("adding APIService ca-injector: %w", err)
	}
	return nil
}

func certMapFunc(cl client.Client) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		return mapCertificateToInjectables(ctx, cl, obj)
	}
}

func secretMapFunc(cl client.Client) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		return mapSecretToInjectables(ctx, cl, obj)
	}
}

func addVWCController(mgr manager.Manager, r *Reconciler) error {
	return builder.
		ControllerManagedBy(mgr).
		Named(controllerVWC).
		For(&admissionv1.ValidatingWebhookConfiguration{}, builder.WithPredicates(HasInjectAnnotationPredicate())).
		Watches(&certv1alpha1.Certificate{}, handler.EnqueueRequestsFromMapFunc(certMapFunc(mgr.GetClient()))).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(secretMapFunc(mgr.GetClient()))).
		Complete(reconcile.Func(func(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
			return r.ReconcileValidatingWebhookConfiguration(ctx, req)
		}))
}

func addMWCController(mgr manager.Manager, r *Reconciler) error {
	return builder.
		ControllerManagedBy(mgr).
		Named(controllerMWC).
		For(&admissionv1.MutatingWebhookConfiguration{}, builder.WithPredicates(HasInjectAnnotationPredicate())).
		Watches(&certv1alpha1.Certificate{}, handler.EnqueueRequestsFromMapFunc(certMapFunc(mgr.GetClient()))).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(secretMapFunc(mgr.GetClient()))).
		Complete(reconcile.Func(func(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
			return r.ReconcileMutatingWebhookConfiguration(ctx, req)
		}))
}

func addCRDController(mgr manager.Manager, r *Reconciler) error {
	return builder.
		ControllerManagedBy(mgr).
		Named(controllerCRD).
		For(&apiextensionsv1.CustomResourceDefinition{}, builder.WithPredicates(HasInjectAnnotationPredicate())).
		Watches(&certv1alpha1.Certificate{}, handler.EnqueueRequestsFromMapFunc(certMapFunc(mgr.GetClient()))).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(secretMapFunc(mgr.GetClient()))).
		Complete(reconcile.Func(func(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
			return r.ReconcileCustomResourceDefinition(ctx, req)
		}))
}

func addAPIServiceController(mgr manager.Manager, r *Reconciler) error {
	return builder.
		ControllerManagedBy(mgr).
		Named(controllerAPIS).
		For(&apiregistrationv1.APIService{}, builder.WithPredicates(HasInjectAnnotationPredicate())).
		Watches(&certv1alpha1.Certificate{}, handler.EnqueueRequestsFromMapFunc(certMapFunc(mgr.GetClient()))).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(secretMapFunc(mgr.GetClient()))).
		Complete(reconcile.Func(func(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
			return r.ReconcileAPIService(ctx, req)
		}))
}

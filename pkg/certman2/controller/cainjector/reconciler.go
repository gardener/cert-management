// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package cainjector

import (
	"context"
	"fmt"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	certv1alpha1 "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
)

const (
	AnnotationInjectCAFrom       = "cert.gardener.cloud/inject-ca-from"
	AnnotationInjectCAFromSecret = "cert.gardener.cloud/inject-ca-from-secret"
	AnnotationAllowDirectInject  = "cert.gardener.cloud/allow-direct-injection"

	requeueDelay = 10 * time.Second
)

// Reconciler holds the shared client for all ca-injector per-kind reconcile methods.
type Reconciler struct {
	Client client.Client
}

// ReconcileValidatingWebhookConfiguration reconciles a ValidatingWebhookConfiguration.
func (r *Reconciler) ReconcileValidatingWebhookConfiguration(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := logf.FromContext(ctx).WithName("cainjector-vwc").WithValues("name", req.Name)

	obj := &admissionv1.ValidatingWebhookConfiguration{}
	if err := r.Client.Get(ctx, req.NamespacedName, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("getting ValidatingWebhookConfiguration: %w", err)
	}

	ca, requeue, err := r.resolveCA(ctx, obj.Annotations)
	if err != nil {
		return reconcile.Result{}, err
	}
	if requeue {
		log.V(1).Info("CA not yet available, requeuing")
		return reconcile.Result{RequeueAfter: requeueDelay}, nil
	}
	if ca == nil {
		return reconcile.Result{}, nil
	}

	patched := obj.DeepCopy()
	for i := range patched.Webhooks {
		patched.Webhooks[i].ClientConfig.CABundle = ca
	}
	return reconcile.Result{}, r.Client.Update(ctx, patched)
}

// ReconcileMutatingWebhookConfiguration reconciles a MutatingWebhookConfiguration.
func (r *Reconciler) ReconcileMutatingWebhookConfiguration(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := logf.FromContext(ctx).WithName("cainjector-mwc").WithValues("name", req.Name)

	obj := &admissionv1.MutatingWebhookConfiguration{}
	if err := r.Client.Get(ctx, req.NamespacedName, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("getting MutatingWebhookConfiguration: %w", err)
	}

	ca, requeue, err := r.resolveCA(ctx, obj.Annotations)
	if err != nil {
		return reconcile.Result{}, err
	}
	if requeue {
		log.V(1).Info("CA not yet available, requeuing")
		return reconcile.Result{RequeueAfter: requeueDelay}, nil
	}
	if ca == nil {
		return reconcile.Result{}, nil
	}

	patched := obj.DeepCopy()
	for i := range patched.Webhooks {
		patched.Webhooks[i].ClientConfig.CABundle = ca
	}
	return reconcile.Result{}, r.Client.Update(ctx, patched)
}

// ReconcileCustomResourceDefinition reconciles a CustomResourceDefinition.
func (r *Reconciler) ReconcileCustomResourceDefinition(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := logf.FromContext(ctx).WithName("cainjector-crd").WithValues("name", req.Name)

	obj := &apiextensionsv1.CustomResourceDefinition{}
	if err := r.Client.Get(ctx, req.NamespacedName, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("getting CustomResourceDefinition: %w", err)
	}

	ca, requeue, err := r.resolveCA(ctx, obj.Annotations)
	if err != nil {
		return reconcile.Result{}, err
	}
	if requeue {
		log.V(1).Info("CA not yet available, requeuing")
		return reconcile.Result{RequeueAfter: requeueDelay}, nil
	}
	if ca == nil {
		return reconcile.Result{}, nil
	}

	if obj.Spec.Conversion == nil || obj.Spec.Conversion.Webhook == nil || obj.Spec.Conversion.Webhook.ClientConfig == nil {
		return reconcile.Result{}, nil
	}

	patched := obj.DeepCopy()
	patched.Spec.Conversion.Webhook.ClientConfig.CABundle = ca
	return reconcile.Result{}, r.Client.Update(ctx, patched)
}

// ReconcileAPIService reconciles an APIService.
func (r *Reconciler) ReconcileAPIService(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := logf.FromContext(ctx).WithName("cainjector-apiservice").WithValues("name", req.Name)

	obj := &apiregistrationv1.APIService{}
	if err := r.Client.Get(ctx, req.NamespacedName, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("getting APIService: %w", err)
	}

	ca, requeue, err := r.resolveCA(ctx, obj.Annotations)
	if err != nil {
		return reconcile.Result{}, err
	}
	if requeue {
		log.V(1).Info("CA not yet available, requeuing")
		return reconcile.Result{RequeueAfter: requeueDelay}, nil
	}
	if ca == nil {
		return reconcile.Result{}, nil
	}

	patched := obj.DeepCopy()
	patched.Spec.CABundle = ca
	return reconcile.Result{}, r.Client.Update(ctx, patched)
}

// resolveCA reads the inject annotation and returns the CA bytes.
// Returns (nil, false, nil) when there is no inject annotation (nothing to do).
// Returns (nil, true, nil) when the CA source exists but has no ca.crt yet (requeue).
// Returns (ca, false, nil) on success.
func (r *Reconciler) resolveCA(ctx context.Context, annotations map[string]string) (ca []byte, requeue bool, err error) {
	if ref, ok := annotations[AnnotationInjectCAFrom]; ok {
		return r.resolveCAFromCertificate(ctx, ref)
	}
	if ref, ok := annotations[AnnotationInjectCAFromSecret]; ok {
		return r.resolveCAFromSecret(ctx, ref, true)
	}
	return nil, false, nil
}

func (r *Reconciler) resolveCAFromCertificate(ctx context.Context, ref string) ([]byte, bool, error) {
	ns, name, err := splitNamespacedName(ref)
	if err != nil {
		return nil, false, fmt.Errorf("invalid inject-ca-from annotation %q: %w", ref, err)
	}

	cert := &certv1alpha1.Certificate{}
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, cert); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("getting Certificate %s/%s: %w", ns, name, err)
	}

	secretName := ""
	if cert.Spec.SecretName != nil {
		secretName = *cert.Spec.SecretName
	} else if cert.Spec.SecretRef != nil {
		secretName = cert.Spec.SecretRef.Name
	}
	if secretName == "" {
		return nil, true, nil
	}

	return r.resolveCAFromSecret(ctx, ns+"/"+secretName, false)
}

func (r *Reconciler) resolveCAFromSecret(ctx context.Context, ref string, checkAllowAnnotation bool) ([]byte, bool, error) {
	ns, name, err := splitNamespacedName(ref)
	if err != nil {
		return nil, false, fmt.Errorf("invalid secret ref %q: %w", ref, err)
	}

	secret := &corev1.Secret{}
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("getting Secret %s/%s: %w", ns, name, err)
	}

	if checkAllowAnnotation {
		if secret.Annotations[AnnotationAllowDirectInject] != "true" {
			return nil, false, nil
		}
	}

	ca := secret.Data["ca.crt"]
	if len(ca) == 0 {
		return nil, true, nil
	}
	return ca, false, nil
}

func splitNamespacedName(ref string) (ns, name string, err error) {
	nn, err := splitSlash(ref)
	if err != nil {
		return "", "", err
	}
	return nn[0], nn[1], nil
}

func splitSlash(s string) ([]string, error) {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return []string{s[:i], s[i+1:]}, nil
		}
	}
	return nil, fmt.Errorf("expected <namespace>/<name>, got %q", s)
}

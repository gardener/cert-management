// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package cainjector

import (
	"context"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	certv1alpha1 "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
)

// mapCertificateToInjectables returns reconcile requests for all injectables
// that reference the changed Certificate via inject-ca-from.
func mapCertificateToInjectables(ctx context.Context, cl client.Client, obj client.Object) []reconcile.Request {
	cert, ok := obj.(*certv1alpha1.Certificate)
	if !ok {
		return nil
	}
	ref := cert.Namespace + "/" + cert.Name
	return allInjectablesWithAnnotation(ctx, cl, AnnotationInjectCAFrom, ref)
}

// mapSecretToInjectables returns reconcile requests for all injectables that
// reference this Secret directly or via a Certificate backed by it.
func mapSecretToInjectables(ctx context.Context, cl client.Client, obj client.Object) []reconcile.Request {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return nil
	}
	ref := secret.Namespace + "/" + secret.Name

	var requests []reconcile.Request
	requests = append(requests, allInjectablesWithAnnotation(ctx, cl, AnnotationInjectCAFromSecret, ref)...)
	requests = append(requests, injectablesForCertBackedBySecret(ctx, cl, secret)...)
	return requests
}

func allInjectablesWithAnnotation(ctx context.Context, cl client.Client, annotation, ref string) []reconcile.Request {
	var out []reconcile.Request
	out = append(out, vwcWithAnnotation(ctx, cl, annotation, ref)...)
	out = append(out, mwcWithAnnotation(ctx, cl, annotation, ref)...)
	out = append(out, crdWithAnnotation(ctx, cl, annotation, ref)...)
	out = append(out, apiServiceWithAnnotation(ctx, cl, annotation, ref)...)
	return out
}

func vwcWithAnnotation(ctx context.Context, cl client.Client, annotation, ref string) []reconcile.Request {
	list := &admissionv1.ValidatingWebhookConfigurationList{}
	if err := cl.List(ctx, list); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range list.Items {
		if list.Items[i].Annotations[annotation] == ref {
			out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
		}
	}
	return out
}

func mwcWithAnnotation(ctx context.Context, cl client.Client, annotation, ref string) []reconcile.Request {
	list := &admissionv1.MutatingWebhookConfigurationList{}
	if err := cl.List(ctx, list); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range list.Items {
		if list.Items[i].Annotations[annotation] == ref {
			out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
		}
	}
	return out
}

func crdWithAnnotation(ctx context.Context, cl client.Client, annotation, ref string) []reconcile.Request {
	list := &apiextensionsv1.CustomResourceDefinitionList{}
	if err := cl.List(ctx, list); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range list.Items {
		if list.Items[i].Annotations[annotation] == ref {
			out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
		}
	}
	return out
}

func apiServiceWithAnnotation(ctx context.Context, cl client.Client, annotation, ref string) []reconcile.Request {
	list := &apiregistrationv1.APIServiceList{}
	if err := cl.List(ctx, list); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range list.Items {
		if list.Items[i].Annotations[annotation] == ref {
			out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
		}
	}
	return out
}

func injectablesForCertBackedBySecret(ctx context.Context, cl client.Client, secret *corev1.Secret) []reconcile.Request {
	certList := &certv1alpha1.CertificateList{}
	if err := cl.List(ctx, certList, client.InNamespace(secret.Namespace)); err != nil {
		return nil
	}
	var out []reconcile.Request
	for _, cert := range certList.Items {
		secretName := ""
		if cert.Spec.SecretName != nil {
			secretName = *cert.Spec.SecretName
		} else if cert.Spec.SecretRef != nil {
			secretName = cert.Spec.SecretRef.Name
		}
		if secretName != secret.Name {
			continue
		}
		ref := cert.Namespace + "/" + cert.Name
		out = append(out, allInjectablesWithAnnotation(ctx, cl, AnnotationInjectCAFrom, ref)...)
	}
	return out
}

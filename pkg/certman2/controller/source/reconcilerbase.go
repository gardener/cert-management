/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package source

import (
	"context"
	"fmt"
	"strings"

	"github.com/gardener/gardener/pkg/utils"
	"github.com/go-logr/logr"
	"golang.org/x/exp/maps"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	certmanv1alpha1 "github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
)

// ReconcilerBase is base for source reconcilers.
type ReconcilerBase struct {
	Client   client.Client
	Recorder record.EventRecorder
	Class    string
	GVK      schema.GroupVersionKind
}

// DoReconcile reconciles for given object and certInput.
func (r *ReconcilerBase) DoReconcile(ctx context.Context, log logr.Logger, obj client.Object, certInputMap CertInputMap) (reconcile.Result, error) {
	newCerts := map[client.ObjectKey]*certmanv1alpha1.Certificate{}
	ownedCerts, err := r.getExistingOwnedCertificates(ctx, client.ObjectKeyFromObject(obj))
	if err != nil {
		return reconcile.Result{}, err
	}
	for key := range certInputMap {
		var matchingCert *certmanv1alpha1.Certificate
		for _, ownedCert := range ownedCerts {
			var refKey client.ObjectKey
			if ownedCert.Spec.SecretRef != nil {
				refKey = client.ObjectKey{Namespace: ownedCert.Spec.SecretRef.Namespace, Name: ownedCert.Spec.SecretRef.Name}
				if refKey.Namespace == "" {
					refKey.Namespace = obj.GetNamespace()
				}
			} else if ownedCert.Spec.SecretName != nil {
				refKey = client.ObjectKey{Namespace: obj.GetNamespace(), Name: *ownedCert.Spec.SecretName}
			}
			if refKey == key {
				matchingCert = &ownedCert
				break
			}
		}
		if matchingCert != nil {
			newCerts[key] = matchingCert
		} else {
			newCerts[key] = r.newCertificate(obj)
		}
	}
	if err := r.deleteObsoleteOwnedCertificates(ctx, log, obj, ownedCerts, maps.Values(newCerts)); err != nil {
		return reconcile.Result{}, err
	}

	for key, newCert := range newCerts {
		if err := r.createOrUpdateCert(ctx, log, obj, certInputMap[key], newCert); err != nil {
			return reconcile.Result{}, err
		}
	}
	return reconcile.Result{}, nil
}

func (r *ReconcilerBase) createOrUpdateCert(ctx context.Context, log logr.Logger, obj client.Object, certInput CertInput, cert *certmanv1alpha1.Certificate) error {
	modifier := func() error {
		cert.Annotations = utils.MergeStringMaps(cert.Annotations, certInput.Annotations)
		cert.Spec = CreateSpec(certInput)
		return nil
	}
	if cert.Name == "" {
		if err := modifier(); err != nil {
			return fmt.Errorf("failed to apply modifier: %w", err)
		}
		if err := r.Client.Create(ctx, cert); err != nil {
			return fmt.Errorf("failed to create certificate: %w", err)
		}
		log.Info("created certificate", "name", cert.Name)
		r.Recorder.Eventf(obj, corev1.EventTypeNormal, "CertificateCreated", "Created certificate: %s", cert.Name) // TODO: check former reason/message
		return nil
	}

	result, err := controllerutil.CreateOrPatch(ctx, r.Client, cert, modifier)
	if err != nil {
		return fmt.Errorf("failed to patch certificate %s: %w", client.ObjectKeyFromObject(cert), err)
	}
	if result == controllerutil.OperationResultUpdated {
		log.Info("certificate has been updated", "name", cert.Name)
		r.Recorder.Eventf(obj, corev1.EventTypeNormal, "CertificateUpdated", "Updated certificate: %s", cert.Name) // TODO: check former reason/message
	}
	return nil
}

// DoDelete performs delete reconciliation for given object.
func (r *ReconcilerBase) DoDelete(ctx context.Context, log logr.Logger, obj client.Object) (reconcile.Result, error) {
	log.Info("deleting")

	ownedCerts, err := r.getExistingOwnedCertificates(ctx, client.ObjectKeyFromObject(obj))
	if err != nil {
		return reconcile.Result{}, err
	}

	if err := r.deleteObsoleteOwnedCertificates(ctx, log, obj, ownedCerts, nil); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func (r *ReconcilerBase) getExistingOwnedCertificates(ctx context.Context, key client.ObjectKey) ([]certmanv1alpha1.Certificate, error) {
	candidates := &certmanv1alpha1.CertificateList{}
	if err := r.Client.List(ctx, candidates, client.InNamespace(key.Namespace)); err != nil {
		return nil, fmt.Errorf("failed to list owned certificates for %s %s: %w", r.GVK.Kind, key, err)
	}

	var ownedCerts []certmanv1alpha1.Certificate
outer:
	for _, candidate := range candidates.Items {
		for _, owner := range candidate.GetOwnerReferences() {
			if owner.Name == key.Name && owner.Kind == r.GVK.Kind && owner.APIVersion == r.GVK.GroupVersion().String() {
				ownedCerts = append(ownedCerts, candidate)
				continue outer
			}
		}
	}
	return ownedCerts, nil
}

func (r *ReconcilerBase) deleteObsoleteOwnedCertificates(
	ctx context.Context,
	log logr.Logger,
	obj client.Object,
	ownedCerts []certmanv1alpha1.Certificate,
	certsToKeep []*certmanv1alpha1.Certificate,
) error {
outer:
	for _, ownedCert := range ownedCerts {
		for _, certToKeep := range certsToKeep {
			if ownedCert.Name == certToKeep.Name {
				continue outer
			}
		}
		if err := r.Client.Delete(ctx, &ownedCert); client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to delete obsolete owned certificate %s: %w", client.ObjectKeyFromObject(&ownedCert), err)
		}
		log.Info("deleted obsolete owned certificate", "name", ownedCert.Name)
		r.Recorder.Eventf(obj, corev1.EventTypeNormal, "CertificateDeleted", "Created certificate: %s", ownedCert.Name) // TODO: check former reason/message
	}
	return nil
}

func (r *ReconcilerBase) newCertificate(obj client.Object) *certmanv1alpha1.Certificate {
	return &certmanv1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("%s-%s-", obj.GetName(), strings.ToLower(r.GVK.Kind)),
			Namespace:    obj.GetNamespace(),
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(obj, r.GVK),
			},
		},
	}
}

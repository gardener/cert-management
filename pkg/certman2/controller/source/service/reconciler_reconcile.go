package service

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	certmanv1alpha1 "github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/certman2/controller/source"
	"github.com/gardener/gardener/pkg/utils"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func (r *Reconciler) reconcile(
	ctx context.Context,
	log logr.Logger,
	service *corev1.Service,
) (
	reconcile.Result,
	error,
) {
	log.Info("reconcile")

	var certInput *source.CertInput
	if isServiceRelevant(service, r.Class) {
		// build certificate from service annotations
		var err error
		certInput, err = r.getCertificateInput(log, service)
		if err != nil {
			r.Recorder.Eventf(service, corev1.EventTypeWarning, "Invalid", "%s", err)
			return reconcile.Result{}, err
		}
	}

	var newCert *certmanv1alpha1.Certificate
	ownedCerts, err := r.getExistingOwnedCertificates(ctx, service)
	if err != nil {
		return reconcile.Result{}, err
	}
	if certInput != nil {
		var matchingCert *certmanv1alpha1.Certificate
		for _, ownedCert := range ownedCerts {
			if reflect.DeepEqual(ownedCert.Spec, source.CreateSpec(*certInput)) {
				matchingCert = &ownedCert
				break
			}
		}
		if matchingCert != nil {
			newCert = matchingCert
		} else if len(ownedCerts) > 0 {
			// reuse first existing certificate
			newCert = &ownedCerts[0]
		} else {
			newCert = &certmanv1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: fmt.Sprintf("%s-%s-", service.Name, strings.ToLower(r.gvk.Kind)),
					Namespace:    service.Namespace,
					OwnerReferences: []metav1.OwnerReference{
						*metav1.NewControllerRef(service, r.gvk),
					},
					Annotations: certInput.Annotations,
				},
				Spec: source.CreateSpec(*certInput),
			}
		}
	}
	if err := r.deleteObsoleteOwnedCertificates(ctx, log, service, ownedCerts, newCert); err != nil {
		return reconcile.Result{}, err
	}

	if newCert == nil {
		return reconcile.Result{}, nil
	}

	if newCert.Name == "" {
		if err := r.Client.Create(ctx, newCert); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to create certificate: %w", err)
		}
		log.Info("created certificate", "name", newCert.Name)
		r.Recorder.Eventf(service, corev1.EventTypeNormal, "CertificateCreated", "Created certificate: %s", newCert.Name) // TODO: check former reason/message
		return reconcile.Result{}, nil
	}

	result, err := controllerutil.CreateOrPatch(ctx, r.Client, newCert, func() error {
		newCert.Annotations = utils.MergeStringMaps(newCert.Annotations, certInput.Annotations)
		newCert.Spec = source.CreateSpec(*certInput)
		return nil
	})
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to patch certificate %s: %w", client.ObjectKeyFromObject(newCert), err)
	}
	if result == controllerutil.OperationResultUpdated {
		log.Info("certificate has been updated", "name", newCert.Name)
		r.Recorder.Eventf(service, corev1.EventTypeNormal, "CertificateUpdated", "Updated certificate: %s", newCert.Name) // TODO: check former reason/message
	}
	return reconcile.Result{}, nil
}

func (r *Reconciler) getCertificateInput(log logr.Logger, service *corev1.Service) (*source.CertInput, error) {
	inputMap, err := source.GetCertSourceSpecForService(log, service)
	if err != nil {
		return nil, err
	}
	if len(inputMap) > 1 {
		return nil, fmt.Errorf("expected one certificate source, found %d", len(inputMap))
	}
	for _, input := range inputMap {
		return &input, nil
	}
	return nil, nil
}

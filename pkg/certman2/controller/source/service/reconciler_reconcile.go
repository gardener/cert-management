package service

import (
	"context"
	"fmt"

	"github.com/gardener/cert-management/pkg/certman2/controller/source"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
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

	var certInputMap source.CertInputMap
	if isRelevant(service, r.Class) {
		// build certificate from service annotations
		var err error
		certInputMap, err = r.getCertificateInputMap(log, service)
		if err != nil {
			r.Recorder.Eventf(service, corev1.EventTypeWarning, "Invalid", "%s", err)
			return reconcile.Result{}, err
		}
	}

	return r.DoReconcile(ctx, log, service, certInputMap)
}

func (r *Reconciler) getCertificateInputMap(log logr.Logger, service *corev1.Service) (source.CertInputMap, error) {
	inputMap, err := source.GetCertSourceSpecForService(log, service)
	if err != nil {
		return nil, err
	}
	if len(inputMap) > 1 {
		return nil, fmt.Errorf("expected one certificate source, found %d", len(inputMap))
	}
	return inputMap, nil
}

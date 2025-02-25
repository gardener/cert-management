// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/cert-management/pkg/certman2/controller/source/common"
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

	var certInputMap common.CertInputMap
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

func (r *Reconciler) getCertificateInputMap(log logr.Logger, service *corev1.Service) (common.CertInputMap, error) {
	inputMap, err := common.GetCertSourceSpecForService(log, service)
	if err != nil {
		return nil, err
	}
	if len(inputMap) > 1 {
		return nil, fmt.Errorf("expected one certificate source, found %d", len(inputMap))
	}
	return inputMap, nil
}

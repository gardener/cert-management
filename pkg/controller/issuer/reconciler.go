/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package issuer

import (
	"github.com/gardener/cert-management/pkg/controller/issuer/acme"
	"github.com/gardener/cert-management/pkg/controller/issuer/ca"
	"github.com/gardener/cert-management/pkg/controller/issuer/certificate"
	"github.com/gardener/cert-management/pkg/controller/issuer/core"
	corev1 "k8s.io/api/core/v1"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
)

func newCompoundReconciler(c controller.Interface) (reconcile.Interface, error) {
	handler, support, err := core.NewHandlerSupport(c, acme.NewACMEIssuerHandler, ca.NewCAIssuerHandler)
	if err != nil {
		return nil, err
	}
	certReconciler, err := certificate.CertReconciler(c, support)
	if err != nil {
		return nil, err
	}

	return &compoundReconciler{
		handler:               handler,
		certificateReconciler: certReconciler,
	}, nil
}

type compoundReconciler struct {
	reconcile.DefaultReconciler
	handler               *core.CompoundHandler
	certificateReconciler reconcile.Interface
}

func (r *compoundReconciler) Setup() {
}

func (r *compoundReconciler) Start() {
	r.certificateReconciler.(reconcile.LegacyStartInterface).Start()
}

func (r *compoundReconciler) Reconcile(logger logger.LogContext, obj resources.Object) reconcile.Status {
	switch {
	case obj.IsA(&api.Issuer{}):
		logger.Infof("reconciling")
		return r.handler.ReconcileIssuer(logger, obj)
	case obj.IsA(&corev1.Secret{}):
		return r.handler.ReconcileSecret(logger, obj)
	case obj.IsA(&api.Certificate{}):
		return r.certificateReconciler.Reconcile(logger, obj)
	}
	return reconcile.Succeeded(logger)
}

func (r *compoundReconciler) Deleted(logger logger.LogContext, objKey resources.ClusterObjectKey) reconcile.Status {
	switch objKey.Kind() {
	case api.CertificateKind:
		return r.certificateReconciler.Deleted(logger, objKey)
	case api.IssuerKind:
		return r.handler.DeletedIssuer(logger, objKey)
	case "Secret":
		return r.handler.DeletedSecret(logger, objKey)
	}

	return reconcile.Succeeded(logger)
}

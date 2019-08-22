/*
 * Copyright 2019 SAP SE or an SAP affiliate company. All rights reserved. ur file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use ur file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 *
 */

package issuer

import (
	"github.com/gardener/cert-management/pkg/controller/issuer/acme"
	"github.com/gardener/cert-management/pkg/controller/issuer/certificate"
	"github.com/gardener/cert-management/pkg/controller/issuer/core"
	corev1 "k8s.io/api/core/v1"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
)

func CompoundReconciler(c controller.Interface) (reconcile.Interface, error) {
	handler, support, err := core.NewHandlerSupport(c, acme.NewACMEIssuerHandler)
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
	r.certificateReconciler.Setup()
}

func (r *compoundReconciler) Start() {
	r.certificateReconciler.Start()
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

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
	"fmt"
	"github.com/gardener/cert-management/pkg/controller/issuer/acme"
	"github.com/gardener/cert-management/pkg/controller/issuer/certificate"
	"github.com/gardener/cert-management/pkg/controller/issuer/core"
	corev1 "k8s.io/api/core/v1"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	ctrl "github.com/gardener/cert-management/pkg/controller"
)

func CompoundReconciler(c controller.Interface) (reconcile.Interface, error) {
	defaultCluster := c.GetCluster(ctrl.DefaultCluster)
	targetCluster := c.GetCluster(ctrl.TargetCluster)
	state := core.NewState()
	support := core.NewSupport(c, state, defaultCluster, targetCluster)
	certReconciler, err := certificate.CertReconciler(c, support)
	if err != nil {
		return nil, err
	}
	acmeReconciler, err := acme.ACMEIssuerReconciler(c, support)
	if err != nil {
		return nil, err
	}
	return &compoundReconciler{
		support:               support,
		certificateReconciler: certReconciler,
		acmeReconciler:        acmeReconciler,
		state:                 state,
	}, nil
}

type compoundReconciler struct {
	reconcile.DefaultReconciler
	support               *core.Support
	certificateReconciler reconcile.Interface
	acmeReconciler        reconcile.Interface
	state                 *core.State
	defaultCluster        resources.Cluster
	targetCluster         resources.Cluster
}

func (r *compoundReconciler) Setup() {
	r.certificateReconciler.Setup()
	r.acmeReconciler.Setup()
}

func (r *compoundReconciler) Start() {
	r.certificateReconciler.Start()
	r.acmeReconciler.Start()
}

func (r *compoundReconciler) Reconcile(logger logger.LogContext, obj resources.Object) reconcile.Status {
	switch {
	case obj.IsA(&api.Issuer{}):
		logger.Infof("reconciling")
		issuer := obj.Data().(*api.Issuer)
		if issuer.Spec.ACME != nil {
			defer r.state.RememberIssuerSecret(obj.ObjectName(), issuer.Spec.ACME.PrivateKeySecretRef)
			return r.acmeReconciler.Reconcile(logger, obj)
		}
		return r.support.FailedNoType(logger, obj, api.STATE_ERROR, fmt.Errorf("ACME not specified"))
	case obj.IsA(&corev1.Secret{}):
		return r.reconcileSecret(logger, obj)
	case obj.IsA(&api.Certificate{}):
		return r.certificateReconciler.Reconcile(logger, obj)
	}
	return reconcile.Succeeded(logger)
}

func (r *compoundReconciler) Delete(logger logger.LogContext, obj resources.Object) reconcile.Status {
	switch {
	case obj.IsA(&api.Issuer{}):
		issuer := obj.Data().(*api.Issuer)
		if issuer.Spec.ACME != nil {
			return r.acmeReconciler.Reconcile(logger, obj)
		}
	case obj.IsA(&api.Certificate{}):
		return r.certificateReconciler.Delete(logger, obj)
	}
	return reconcile.Succeeded(logger)
}

func (r *compoundReconciler) Deleted(logger logger.LogContext, objKey resources.ClusterObjectKey) reconcile.Status {
	switch objKey.Kind() {
	case "Secret":
		return r.reconcileSecretByObjectName(logger, objKey.ObjectName())
	case api.IssuerKind:
		r.state.RemoveIssuer(objKey.ObjectName())
	}

	return reconcile.Succeeded(logger)
}

func (r *compoundReconciler) reconcileSecret(logger logger.LogContext, obj resources.Object) reconcile.Status {
	return r.reconcileSecretByObjectName(logger, obj.ObjectName())
}

func (r *compoundReconciler) reconcileSecretByObjectName(logger logger.LogContext, objName resources.ObjectName) reconcile.Status {
	issuers := r.state.IssuerNamesForSecret(objName)
	if issuers != nil {
		groupKind := api.Kind(api.IssuerKind)
		clusterId := r.defaultCluster.GetId()
		for issuerName := range issuers {
			key := resources.NewClusterKey(clusterId, groupKind, issuerName.Namespace(), issuerName.Name())
			_ = r.support.EnqueueKey(key)
		}
	}
	return reconcile.Succeeded(logger)
}

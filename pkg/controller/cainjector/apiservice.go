/*
 * SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package cainjector

import (
	"bytes"
	"time"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	ctrl "github.com/gardener/cert-management/pkg/controller"
)

func init() {
	controller.Configure("cainjector-apiservice").
		Reconciler(newAPIServiceReconciler).
		Cluster(ctrl.SourceCluster).
		DefaultWorkerPool(1, 0*time.Second).
		MainResource(apiregistrationv1.GroupName, "APIService").
		WorkerPool("certificates", 1, 0).
		Watch(api.GroupName, api.CertificateKind).
		WorkerPool("secrets", 1, 0).
		Watch("core", "Secret").
		MustRegister(ctrl.ControllerGroupCAInjector)
}

type apiServiceReconciler struct {
	reconcile.DefaultReconciler
	*injector
}

var _ reconcile.Interface = &apiServiceReconciler{}

func newAPIServiceReconciler(c controller.Interface) (reconcile.Interface, error) {
	inj, err := newInjector(c)
	if err != nil {
		return nil, err
	}
	return &apiServiceReconciler{injector: inj}, nil
}

func (r *apiServiceReconciler) Reconcile(logger logger.LogContext, obj resources.Object) reconcile.Status {
	if isCASource(obj) {
		return r.enqueueReferers(logger, obj.ClusterKey())
	}
	return r.reconcileInjectable(logger, obj)
}

func (r *apiServiceReconciler) reconcileInjectable(logger logger.LogContext, obj resources.Object) reconcile.Status {
	apiService := obj.Data().(*apiregistrationv1.APIService)
	r.trackRefs(obj.ClusterKey(), apiService.Namespace, apiService.Annotations)

	ca, requeue, err := r.resolveCA(apiService.Namespace, apiService.Annotations)
	if err != nil {
		return reconcile.Delay(logger, err)
	}
	if requeue {
		logger.Infof("CA not yet available, requeuing")
		return reconcile.RescheduleAfter(logger, requeueDelay)
	}
	if ca == nil {
		return reconcile.Succeeded(logger)
	}

	if _, err := obj.Modify(func(data resources.ObjectData) (bool, error) {
		apiService := data.(*apiregistrationv1.APIService)
		if bytes.Equal(apiService.Spec.CABundle, ca) {
			return false, nil
		}
		apiService.Spec.CABundle = ca
		return true, nil
	}); err != nil {
		return reconcile.Delay(logger, err)
	}
	return reconcile.Succeeded(logger)
}

func (r *apiServiceReconciler) Deleted(logger logger.LogContext, key resources.ClusterObjectKey) reconcile.Status {
	if isCASourceKind(key.Kind()) {
		return r.enqueueReferers(logger, key)
	}
	r.forgetRefs(key)
	return reconcile.Succeeded(logger)
}

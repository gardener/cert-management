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
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	ctrl "github.com/gardener/cert-management/pkg/controller"
)

func init() {
	controller.Configure("cainjector-crd").
		Reconciler(newCRDReconciler).
		Cluster(ctrl.SourceCluster).
		DefaultWorkerPool(1, 0*time.Second).
		MainResource(apiextensionsv1.GroupName, "CustomResourceDefinition").
		WorkerPool("certificates", 1, 0).
		Watch(api.GroupName, api.CertificateKind).
		WorkerPool("secrets", 1, 0).
		Watch("core", "Secret").
		ActivateExplicitly().
		MustRegister(ctrl.ControllerGroupCAInjector)
}

type crdReconciler struct {
	reconcile.DefaultReconciler
	*injector
}

var _ reconcile.Interface = &crdReconciler{}

func newCRDReconciler(c controller.Interface) (reconcile.Interface, error) {
	inj, err := newInjector(c)
	if err != nil {
		return nil, err
	}
	return &crdReconciler{injector: inj}, nil
}

func (r *crdReconciler) Reconcile(logger logger.LogContext, obj resources.Object) reconcile.Status {
	if isCASource(obj) {
		return r.enqueueReferers(logger, obj.ClusterKey())
	}
	return r.reconcileInjectable(logger, obj)
}

func (r *crdReconciler) reconcileInjectable(logger logger.LogContext, obj resources.Object) reconcile.Status {
	crd := obj.Data().(*apiextensionsv1.CustomResourceDefinition)
	r.trackRefs(obj.ClusterKey(), crd.Namespace, crd.Annotations)

	ca, requeue, err := r.resolveCA(crd.Namespace, crd.Annotations)
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
		crd := data.(*apiextensionsv1.CustomResourceDefinition)
		conversion := crd.Spec.Conversion
		if conversion == nil || conversion.Strategy != apiextensionsv1.WebhookConverter || conversion.Webhook == nil {
			return false, nil
		}
		if conversion.Webhook.ClientConfig == nil {
			conversion.Webhook.ClientConfig = &apiextensionsv1.WebhookClientConfig{}
		}
		if bytes.Equal(conversion.Webhook.ClientConfig.CABundle, ca) {
			return false, nil
		}
		conversion.Webhook.ClientConfig.CABundle = ca
		return true, nil
	}); err != nil {
		return reconcile.Delay(logger, err)
	}
	return reconcile.Succeeded(logger)
}

func (r *crdReconciler) Deleted(logger logger.LogContext, key resources.ClusterObjectKey) reconcile.Status {
	if isCASourceKind(key.Kind()) {
		return r.enqueueReferers(logger, key)
	}
	r.forgetRefs(key)
	return reconcile.Succeeded(logger)
}

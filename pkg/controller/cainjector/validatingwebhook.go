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
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	ctrl "github.com/gardener/cert-management/pkg/controller"
)

func init() {
	controller.Configure("cainjector-validatingwebhook").
		Reconciler(newValidatingWebhookReconciler).
		Cluster(ctrl.SourceCluster).
		DefaultWorkerPool(1, 0*time.Second).
		MainResource(admissionregistrationv1.GroupName, "ValidatingWebhookConfiguration").
		WorkerPool("certificates", 1, 0).
		Watch(api.GroupName, api.CertificateKind).
		WorkerPool("secrets", 1, 0).
		Watch("core", "Secret").
		MustRegister(ctrl.ControllerGroupCAInjector)
}

type validatingWebhookReconciler struct {
	reconcile.DefaultReconciler
	*injector
}

var _ reconcile.Interface = &validatingWebhookReconciler{}

func newValidatingWebhookReconciler(c controller.Interface) (reconcile.Interface, error) {
	inj, err := newInjector(c)
	if err != nil {
		return nil, err
	}
	return &validatingWebhookReconciler{injector: inj}, nil
}

func (r *validatingWebhookReconciler) Reconcile(logger logger.LogContext, obj resources.Object) reconcile.Status {
	if isCASource(obj) {
		return r.enqueueReferers(logger, obj.ClusterKey())
	}
	return r.reconcileInjectable(logger, obj)
}

func (r *validatingWebhookReconciler) reconcileInjectable(logger logger.LogContext, obj resources.Object) reconcile.Status {
	config := obj.Data().(*admissionregistrationv1.ValidatingWebhookConfiguration)
	r.trackRefs(obj.ClusterKey(), config.Namespace, config.Annotations)

	ca, requeue, err := r.resolveCA(config.Namespace, config.Annotations)
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
		config := data.(*admissionregistrationv1.ValidatingWebhookConfiguration)
		changed := false
		for i := range config.Webhooks {
			if !bytes.Equal(config.Webhooks[i].ClientConfig.CABundle, ca) {
				config.Webhooks[i].ClientConfig.CABundle = ca
				changed = true
			}
		}
		return changed, nil
	}); err != nil {
		return reconcile.Delay(logger, err)
	}
	return reconcile.Succeeded(logger)
}

func (r *validatingWebhookReconciler) Deleted(logger logger.LogContext, key resources.ClusterObjectKey) reconcile.Status {
	if isCASourceKind(key.Kind()) {
		return r.enqueueReferers(logger, key)
	}
	r.forgetRefs(key)
	return reconcile.Succeeded(logger)
}

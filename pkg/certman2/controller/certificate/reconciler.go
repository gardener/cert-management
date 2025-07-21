// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package certificate

import (
	"context"
	"fmt"
	"k8s.io/utils/ptr"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/certman2/apis/config"
	"github.com/gardener/cert-management/pkg/shared/legobridge"
)

// Reconciler is a reconciler for provided Certificate resources.
type Reconciler struct {
	Client   client.Client
	Clock    clock.Clock
	Recorder record.EventRecorder
	Config   config.CertManagerConfiguration

	pendingRequests *legobridge.PendingCertificateRequests
	pendingResults  *legobridge.PendingResults
}

// Reconcile reconciles Certificate resources.
func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := logf.FromContext(ctx).WithName(ControllerName).WithValues(
		"namespace", req.Namespace,
		"name", req.Name,
	)

	cert := &v1alpha1.Certificate{}
	if err := r.Client.Get(ctx, req.NamespacedName, cert); err != nil {
		if apierrors.IsNotFound(err) {
			log.V(1).Info("Object is gone, stop reconciling")
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("error retrieving object from store: %w", err)
	}

	var (
		result     reconcile.Result
		err        error
		oldMessage = ptr.Deref(cert.Status.Message, "")
	)
	if cert.DeletionTimestamp != nil {
		result, err = r.delete(ctx, log, cert)
	} else {
		result, err = r.reconcile(ctx, log, cert)
	}

	r.handleChangedMessage(cert, oldMessage, err)

	return result, err
}

func (r *Reconciler) handleChangedMessage(cert *v1alpha1.Certificate, oldMessage string, err error) {
	newMessage := ptr.Deref(cert.Status.Message, "")
	if newMessage == oldMessage {
		return
	}

	eventType := corev1.EventTypeNormal
	if err != nil {
		eventType = corev1.EventTypeWarning
		newMessage = fmt.Sprintf("%s, error: %s", newMessage, err)
	}

	r.Recorder.Event(cert, eventType, "StatusChanged", newMessage)
}

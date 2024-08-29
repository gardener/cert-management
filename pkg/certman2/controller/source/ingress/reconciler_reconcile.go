package ingress

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/cert-management/pkg/certman2/controller/source"
)

func (r *Reconciler) reconcile(
	ctx context.Context,
	log logr.Logger,
	ingress *networkingv1.Ingress,
) (
	reconcile.Result,
	error,
) {
	log.Info("reconcile")

	var certInputMap source.CertInputMap
	if isRelevant(ingress, r.Class) {
		var err error
		certInputMap, err = r.getCertificateInputMap(log, ingress)
		if err != nil {
			r.Recorder.Eventf(ingress, corev1.EventTypeWarning, "Invalid", "%s", err)
			return reconcile.Result{}, err
		}
	}

	return r.DoReconcile(ctx, log, ingress, certInputMap)
}

func (r *Reconciler) getCertificateInputMap(log logr.Logger, ingress *networkingv1.Ingress) (source.CertInputMap, error) {
	return source.GetCertInputByCollector(log, ingress, func(obj client.Object) ([]*source.TLSData, error) {
		data, ok := obj.(*networkingv1.Ingress)
		if !ok {
			return nil, fmt.Errorf("unexpected ingress type: %t", obj)
		}
		if data.Spec.TLS == nil {
			return nil, nil
		}
		var array []*source.TLSData
		for _, item := range data.Spec.TLS {
			array = append(array, &source.TLSData{
				SecretNamespace: obj.GetNamespace(),
				SecretName:      item.SecretName,
				Hosts:           item.Hosts,
			})
		}
		return array, nil
	})
}

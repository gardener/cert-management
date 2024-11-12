/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package issuer

import (
	"fmt"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/cert/utils"
	ctrl "github.com/gardener/cert-management/pkg/controller"
	"github.com/gardener/cert-management/pkg/controller/issuer/acme"
	"github.com/gardener/cert-management/pkg/controller/issuer/ca"
	"github.com/gardener/cert-management/pkg/controller/issuer/certificate"
	"github.com/gardener/cert-management/pkg/controller/issuer/core"
	"github.com/gardener/cert-management/pkg/controller/issuer/revocation"
)

func newCompoundReconciler(c controller.Interface) (reconcile.Interface, error) {
	handler, err := core.NewCompoundHandler(c, acme.NewACMEIssuerHandler, ca.NewCAIssuerHandler)
	if err != nil {
		return nil, err
	}
	certReconciler, err := certificate.CertReconciler(c, handler.Support())
	if err != nil {
		return nil, err
	}
	revokeReconciler, err := revocation.RevokeReconciler(c, handler.Support())
	if err != nil {
		return nil, err
	}
	allowTargetIssuers, _ := c.GetBoolOption(core.OptAllowTargetIssuers)
	if allowTargetIssuers && c.GetCluster(ctrl.DefaultCluster) == c.GetCluster(ctrl.TargetCluster) {
		return nil, fmt.Errorf("command line option '--%s' is only supported if default cluster != target cluster", core.OptAllowTargetIssuers)
	}

	return &compoundReconciler{
		handler:                         handler,
		certificateReconciler:           certReconciler,
		certificateRevocationReconciler: revokeReconciler,
		watchTargetIssuers:              allowTargetIssuers,
	}, nil
}

type compoundReconciler struct {
	reconcile.DefaultReconciler
	handler                         *core.CompoundHandler
	certificateReconciler           reconcile.Interface
	certificateRevocationReconciler reconcile.Interface
	watchTargetIssuers              bool
}

func (r *compoundReconciler) Setup() error {
	err := r.setupIssuers(utils.ClusterDefault)
	if err != nil {
		return err
	}
	if r.watchTargetIssuers {
		err = r.setupIssuers(utils.ClusterTarget)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *compoundReconciler) setupIssuers(cluster utils.Cluster) error {
	dummyKey := utils.NewIssuerKey(cluster, "dummy", "dummy")
	res := r.handler.Support().GetIssuerResources(dummyKey)
	list, err := res.Namespace(r.handler.Support().IssuerNamespace()).List(v1.ListOptions{})
	if err != nil {
		return err
	}
	for _, obj := range list {
		issuer := obj.Data().(*api.Issuer)
		if issuer.Spec.ACME != nil {
			r.handler.Support().AddIssuerDomains(obj.ClusterKey(), issuer.Spec.ACME.Domains)
		}
	}
	return nil
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
	case obj.IsA(&api.CertificateRevocation{}):
		return r.certificateRevocationReconciler.Reconcile(logger, obj)
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

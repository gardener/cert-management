// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package crdwatch

import (
	"os"
	"time"

	ctrl "github.com/gardener/cert-management/pkg/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Controller is the controller name.
const Controller = "watch-gateways-crds"

func init() {
	controller.Configure(Controller).
		Reconciler(Create).
		DefaultWorkerPool(1, 0*time.Second).
		MainResource(apiextensionsv1.GroupName, "CustomResourceDefinition").
		MustRegister(ctrl.ControllerGroupSource)
}

type reconciler struct {
	reconcile.DefaultReconciler
	controller controller.Interface

	relevantCustomResourceDefinitionDeployed map[string]bool
}

var _ reconcile.Interface = &reconciler{}

///////////////////////////////////////////////////////////////////////////////

// Create creates the controller to watch for gateway CRDs.
func Create(controller controller.Interface) (reconcile.Interface, error) {
	return &reconciler{
		controller: controller,
		relevantCustomResourceDefinitionDeployed: map[string]bool{
			"gateways.networking.istio.io":         false,
			"virtualservices.networking.istio.io":  false,
			"gateways.gateway.networking.k8s.io":   false,
			"httproutes.gateway.networking.k8s.io": false,
		},
	}, nil
}

func (r *reconciler) Setup() error {
	r.controller.Infof("### setup crds watch resources")
	res, err := r.controller.GetMainCluster().Resources().GetByExample(&apiextensionsv1.CustomResourceDefinition{})
	if err != nil {
		return err
	}
	list, err := res.ListCached(labels.Everything())
	if err != nil {
		return err
	}
	for _, item := range list {
		crd := item.Data().(*apiextensionsv1.CustomResourceDefinition)
		switch crd.Spec.Group {
		case "networking.istio.io", "gateway.networking.k8s.io":
			name := crdName(crd)
			if _, relevant := r.relevantCustomResourceDefinitionDeployed[name]; relevant {
				r.relevantCustomResourceDefinitionDeployed[name] = true
			}
		}
	}
	return nil
}

///////////////////////////////////////////////////////////////////////////////

func (r *reconciler) Reconcile(logger logger.LogContext, obj resources.Object) reconcile.Status {
	crd := obj.Data().(*apiextensionsv1.CustomResourceDefinition)
	name := crdName(crd)
	if alreadyDeployed, relevant := r.relevantCustomResourceDefinitionDeployed[name]; relevant && !alreadyDeployed {
		logger.Infof("new relevant CRD %s deployed: need to restart to initialise controller", name)
		os.Exit(2)
	}
	return reconcile.Succeeded(logger)
}

func (r *reconciler) Delete(logger logger.LogContext, obj resources.Object) reconcile.Status {
	crd := obj.Data().(*apiextensionsv1.CustomResourceDefinition)
	name := crdName(crd)
	if alreadyDeployed, relevant := r.relevantCustomResourceDefinitionDeployed[name]; relevant && alreadyDeployed {
		logger.Infof("new relevant CRD %s deleted: need to restart to disable controllers", name)
		os.Exit(3)
	}
	return reconcile.Succeeded(logger)
}

func (r *reconciler) Deleted(logger logger.LogContext, _ resources.ClusterObjectKey) reconcile.Status {
	return reconcile.Succeeded(logger)
}

func crdName(crd *apiextensionsv1.CustomResourceDefinition) string {
	return crd.Spec.Names.Plural + "." + crd.Spec.Group
}

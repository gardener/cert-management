/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package source

import (
	"k8s.io/apimachinery/pkg/api/errors"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile/reconcilers"
)

// SlaveReconcilerType creates a slaveReconciler.
func SlaveReconcilerType(c controller.Interface) (reconcile.Interface, error) {
	reconciler := &slaveReconciler{
		controller: c,
		slaves:     c.(*reconcilers.SlaveReconciler),
	}
	return reconciler, nil
}

type slaveReconciler struct {
	reconcile.DefaultReconciler
	controller controller.Interface
	slaves     *reconcilers.SlaveReconciler
}

func (r *slaveReconciler) Start() {
	r.controller.Infof("determining dangling certificates...")
	cluster := r.controller.GetMainCluster()
	main := cluster.GetId()
	for k := range r.slaves.GetMasters(false) {
		if k.Cluster() == main {
			if _, err := cluster.GetCachedObject(k); errors.IsNotFound(err) {
				r.controller.Infof("trigger vanished origin %s", k.ObjectKey())
				r.controller.EnqueueKey(k)
			} else {
				r.controller.Debugf("found origin %s", k.ObjectKey())
			}
		}
	}
}

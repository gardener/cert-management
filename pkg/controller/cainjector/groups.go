/*
 * SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package cainjector

import (
	cgroups "github.com/gardener/controller-manager-library/pkg/controllermanager/controller/groups"

	ctrl "github.com/gardener/cert-management/pkg/controller"
)

func init() {
	cgroups.MustRegister(ctrl.ControllerGroupCAInjector).ActivateExplicitly(
		"cainjector-validatingwebhook",
		"cainjector-mutatingwebhook",
		"cainjector-crd",
		"cainjector-apiservice",
	)
}

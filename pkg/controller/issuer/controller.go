/*
 * Copyright 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
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
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"

	"github.com/gardener/cert-management/pkg/apis/cert"
	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	crds "github.com/gardener/cert-management/pkg/cert"
	ctrl "github.com/gardener/cert-management/pkg/controller"
)

const ControllerIssuer = "issuer"
const ACMEType = "acme"

func init() {
	controller.Configure(ControllerIssuer).
		FinalizerDomain(cert.GroupName).
		Cluster(ctrl.DefaultCluster).
		CustomResourceDefinitions(crds.IssuerCRD).
		DefaultWorkerPool(1, 0).
		MainResource(api.GroupName, api.IssuerKind).
		Reconciler(IssuerReconciler).
		WorkerPool("secrets", 1, 0).
		Watches(
			controller.NewResourceKey("core", "Secret"),
		).
		MustRegister(ctrl.ControllerGroupCert)
}

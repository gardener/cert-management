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

package source

import (
	"time"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile/reconcilers"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/external-dns-management/pkg/dns/utils"
	"k8s.io/apimachinery/pkg/runtime/schema"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	crds "github.com/gardener/cert-management/pkg/cert"
	ctrl "github.com/gardener/cert-management/pkg/controller"
)

// services share dnsnames
const ANNOT_DNSNAMES = "dns.gardener.cloud/dnsnames"
const ANNOT_CLASS = "cert.gardener.cloud/class"
const ANNOT_SECRETNAME = "cert.gardener.cloud/secretname"
const ANNOT_ISSUER = "cert.gardener.cloud/issuer"

const OPT_CLASS = "cert-class"
const OPT_TARGETCLASS = "cert-target-class"
const OPT_NAMESPACE = "target-namespace"
const OPT_NAMEPREFIX = "target-name-prefix"

var REQUEST = resources.NewGroupKind(api.GroupName, api.CertificateKind)

func CertSourceController(source CertSourceType, reconcilerType controller.ReconcilerType) controller.Configuration {
	gk := source.GroupKind()
	return controller.Configure(source.Name()).
		DefaultedStringOption(OPT_CLASS, utils.DEFAULT_CLASS, "Identifier used to differentiate responsible controllers for entries").
		StringOption(OPT_TARGETCLASS, "Identifier used to differentiate responsible dns controllers for target entries").
		DefaultedStringOption(OPT_NAMESPACE, "", "target namespace for cross cluster generation").
		DefaultedStringOption(OPT_NAMEPREFIX, "", "name prefix in target namespace for cross cluster generation").
		FinalizerDomain(api.GroupName).
		Reconciler(SourceReconciler(source, reconcilerType)).
		Cluster(ctrl.SourceCluster).
		DefaultWorkerPool(2, 120*time.Second).
		MainResource(gk.Group, gk.Kind).
		Reconciler(reconcilers.SlaveReconcilerType(source.Name(), SlaveResources, SlaveReconcilerType, MasterResourcesType(source.GroupKind())), "certificates").
		Cluster(ctrl.TargetCluster).
		CustomResourceDefinitions(crds.CertificateCRD).
		WorkerPool("targets", 2, 0).
		ReconcilerWatch("certificates", api.GroupName, api.CertificateKind)
}

var SlaveResources = reconcilers.ClusterResources(ctrl.TargetCluster, REQUEST)

func MasterResourcesType(kind schema.GroupKind) reconcilers.Resources {
	return func(c controller.Interface) []resources.Interface {
		target := c.GetMainCluster()
		res, err := target.Resources().GetByGK(kind)
		if err != nil {
			panic(err)
		}
		return []resources.Interface{res}
	}
}

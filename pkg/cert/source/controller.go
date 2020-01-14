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
	"k8s.io/apimachinery/pkg/runtime/schema"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	crds "github.com/gardener/cert-management/pkg/cert"
	ctrl "github.com/gardener/cert-management/pkg/controller"
)

const (
	// AnnotDnsnames annotation is shared with dns controller manager
	AnnotDnsnames = "dns.gardener.cloud/dnsnames"
	// AnnotDNSClass is the annotation for the dns class
	AnnotDNSClass = "dns.gardener.cloud/class"
	// AnnotClass is the annotation for the cert class
	AnnotClass = "cert.gardener.cloud/class"
	// AnnotForwardOwnerRefs is the annotation for the forward owner references
	AnnotForwardOwnerRefs = "cert.gardener.cloud/forward-owner-refs"
	// AnnotSecretname is the annotation for the secret name
	AnnotSecretname = "cert.gardener.cloud/secretname"
	// AnnotIssuer is the annotation for the issuer name
	AnnotIssuer = "cert.gardener.cloud/issuer"

	// OptClass is the cert-class command line option
	OptClass = "cert-class"
	// OptTargetclass is the target-cert-class command line option
	OptTargetclass = "cert-target-class"
	// OptNamespace is the namespace command line option
	OptNamespace = "target-namespace"
	// OptNameprefix is the target-name-prefix command line option
	OptNameprefix = "target-name-prefix"

	// DefaultClass is the default cert-class
	DefaultClass = "gardencert"
)

var certificateGroupKind = resources.NewGroupKind(api.GroupName, api.CertificateKind)

// CertSourceController creates a CertSource controller.
func CertSourceController(source CertSourceType, reconcilerType controller.ReconcilerType) controller.Configuration {
	gk := source.GroupKind()
	return controller.Configure(source.Name()).
		DefaultedStringOption(OptClass, DefaultClass, "Identifier used to differentiate responsible controllers for entries").
		StringOption(OptTargetclass, "Identifier used to differentiate responsible dns controllers for target entries").
		DefaultedStringOption(OptNamespace, "", "target namespace for cross cluster generation").
		DefaultedStringOption(OptNameprefix, "", "name prefix in target namespace for cross cluster generation").
		FinalizerDomain(api.GroupName).
		Reconciler(SrcReconciler(source, reconcilerType)).
		Cluster(ctrl.SourceCluster).
		DefaultWorkerPool(2, 120*time.Second).
		MainResource(gk.Group, gk.Kind).
		Reconciler(reconcilers.SlaveReconcilerType(source.Name(), slaveResources, SlaveReconcilerType, MasterResourcesType(source.GroupKind())), "certificates").
		Cluster(ctrl.TargetCluster).
		CustomResourceDefinitions(crds.CertificateCRD).
		WorkerPool("targets", 2, 0).
		ReconcilerWatch("certificates", api.GroupName, api.CertificateKind)
}

var slaveResources = reconcilers.ClusterResources(ctrl.TargetCluster, certificateGroupKind)

// MasterResourcesType creates the master resource type interfaces function.
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

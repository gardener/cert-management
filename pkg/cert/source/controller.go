/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package source

import (
	"time"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile/reconcilers"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"k8s.io/apimachinery/pkg/runtime/schema"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
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
	// AnnotCommonName is the annotation for explicitly specifying the common name
	AnnotCommonName = "cert.gardener.cloud/commonname"
	// AnnotCertDNSNames is the annotation for explicitly specifying the DNS names (if not specified, values from "dns.gardener.cloud/dnsnames" is used)
	AnnotCertDNSNames = "cert.gardener.cloud/dnsnames"

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

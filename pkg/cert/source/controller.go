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
	// AnnotACMEDNSChallenge is the annotation for marking DNSEntries for DNS challenges
	AnnotACMEDNSChallenge = "cert.gardener.cloud/acme-dns-challenge"
	// AnnotForwardOwnerRefs is the annotation for the forward owner references
	AnnotForwardOwnerRefs = "cert.gardener.cloud/forward-owner-refs"
	// AnnotSecretname is the annotation for the secret name
	AnnotSecretname = "cert.gardener.cloud/secretname" // #nosec G101 -- this is no credential
	// AnnotSecretNamespace is the annotation for the TLS secret namespace (only used for Istio Gateways source resources)
	AnnotSecretNamespace = "cert.gardener.cloud/secret-namespace" // #nosec G101 -- this is no credential
	// AnnotIssuer is the annotation for the issuer name
	AnnotIssuer = "cert.gardener.cloud/issuer"
	// AnnotCommonName is the annotation for explicitly specifying the common name
	AnnotCommonName = "cert.gardener.cloud/commonname"
	// AnnotCertDNSNames is the annotation for explicitly specifying the DNS names (if not specified, values from "dns.gardener.cloud/dnsnames" is used)
	AnnotCertDNSNames = "cert.gardener.cloud/dnsnames"
	// AnnotFollowCNAME is the annotation for allowing delegated domains for DNS01 challenge
	AnnotFollowCNAME = "cert.gardener.cloud/follow-cname"
	// AnnotCertSecretLabels is the annotation for setting labels for the secret resource
	// comma-separated format "key1=value1,key2=value2"
	AnnotCertSecretLabels = "cert.gardener.cloud/secret-labels" // #nosec G101 -- this is no credential
	// AnnotPreferredChain is the annotation for the certificate preferred chain
	AnnotPreferredChain = "cert.gardener.cloud/preferred-chain"

	// AnnotDNSRecordProviderType is the annotation for providing the provider type for DNS records.
	AnnotDNSRecordProviderType = api.GroupName + "/dnsrecord-provider-type"
	// AnnotDNSRecordSecretRef is the annotation for providing the secret ref for DNS records.
	AnnotDNSRecordSecretRef = api.GroupName + "/dnsrecord-secret-ref"
	// AnnotDNSRecordClass is an optional annotation for providing the extension class for DNS records.
	AnnotDNSRecordClass = api.GroupName + "/dnsrecord-class"

	// AnnotPrivateKeyAlgorithm is the annotation key to set the PrivateKeyAlgorithm for a Certificate.
	// If PrivateKeyAlgorithm is specified and `size` is not provided,
	// key size of 256 will be used for `ECDSA` key algorithm and
	// key size of 2048 will be used for `RSA` key algorithm.
	// If unset an algorithm `RSA` will be used.
	AnnotPrivateKeyAlgorithm = "cert.gardener.cloud/private-key-algorithm"

	// AnnotPrivateKeySize is the annotation key to set the size of the private key for a Certificate.
	// If PrivateKeyAlgorithm is set to `RSA`, valid values are `2048`, `3072`, or `4096`,
	// and will default to `2048` if not specified.
	// If PrivateKeyAlgorithm is set to `ECDSA`, valid values are `256` or `384`,
	// and will default to `256` if not specified.
	// No other values are allowed.
	AnnotPrivateKeySize = "cert.gardener.cloud/private-key-size"

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
	return func(c controller.Interface) ([]resources.Interface, error) {
		target := c.GetMainCluster()
		res, err := target.Resources().GetByGK(kind)
		if err != nil {
			return nil, err
		}
		return []resources.Interface{res}, nil
	}
}

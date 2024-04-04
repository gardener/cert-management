/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"os"
	"strings"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	networkingv1beta1 "k8s.io/api/networking/v1beta1"

	"github.com/gardener/controller-manager-library/pkg/controllermanager"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/cluster"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/mappings"
	"github.com/gardener/controller-manager-library/pkg/resources"

	dnsapi "github.com/gardener/external-dns-management/pkg/apis/dns/v1alpha1"

	"github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	ctrl "github.com/gardener/cert-management/pkg/controller"
	_ "github.com/gardener/cert-management/pkg/controller/issuer"
	_ "github.com/gardener/cert-management/pkg/controller/source/ingress"
	_ "github.com/gardener/cert-management/pkg/controller/source/service"
	"github.com/gardener/cert-management/pkg/deployer/gen"
)

var version string

func init() {
	cluster.Configure(
		ctrl.TargetCluster,
		"target",
		"target cluster for certificates",
	).Fallback(ctrl.SourceCluster).MustRegister()

	cluster.Configure(
		ctrl.SourceCluster,
		"source",
		"source cluster to watch for ingresses and services",
	).MustRegister()

	cluster.Configure(
		ctrl.DNSCluster,
		"dns",
		"cluster for writing challenge DNS entries",
	).MustRegister()

	mappings.ForControllerGroup(ctrl.ControllerGroupCert).
		MustRegister()

	mappings.ForControllerGroup(ctrl.ControllerGroupSource).
		MustRegister()

	resources.Register(networkingv1beta1.SchemeBuilder)
	resources.Register(networkingv1.SchemeBuilder)
	resources.Register(corev1.SchemeBuilder)
	resources.Register(dnsapi.SchemeBuilder)
	resources.Register(v1alpha1.SchemeBuilder)
	resources.Register(coordinationv1.SchemeBuilder)
}

func main() {
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		switch os.Args[1] {
		case "version":
			fmt.Println(version)
			os.Exit(0)
		case "generate-manifests":
			os.Exit(gen.GenerateWithArgs(os.Args[2:], os.Args[1]))
		default:
			fmt.Println("Supported subcommand are:")
			fmt.Printf("    %s version\n", os.Args[0])
			fmt.Printf("    %s generate-manifests --values <values-file> --output <output-file>\n", os.Args[0])
			os.Exit(1)
		}
	}

	// set LEGO_DISABLE_CNAME_SUPPORT=true as we have our own logic for FollowCNAME
	os.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	controllermanager.Start("cert-controller-manager", "Certificate controller manager", "The cert-manager manages TLS certificates in Kubernetes clusters using custom resources")
}

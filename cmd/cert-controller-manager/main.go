/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"os"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
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
	resources.Register(corev1.SchemeBuilder)
	resources.Register(dnsapi.SchemeBuilder)
	resources.Register(v1alpha1.SchemeBuilder)
	resources.Register(coordinationv1.SchemeBuilder)
}

func migrateExtensionsIngress(c controllermanager.Configuration) controllermanager.Configuration {
	return c.GlobalGroupKindMigrations(resources.NewGroupKind("extensions", "Ingress"),
		resources.NewGroupKind("networking.k8s.io", "Ingress"))
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(version)
		os.Exit(0)
	}
	controllermanager.Start("cert-controller-manager", "Certificate controller manager", "nothing", migrateExtensionsIngress)
}

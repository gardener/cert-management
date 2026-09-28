/*
 * SPDX-FileCopyrightText: Contributors to the Gardener project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package controller

import (
	"github.com/gardener/controller-manager-library/pkg/controllermanager/cluster"
)

const (
	// ControllerGroupCert is the controller group for certificates and issuers
	ControllerGroupCert = "certcontrollers"
	// ControllerGroupSource is the controller group for sources (ingress and services)
	ControllerGroupSource = "certsources"
	// ControllerGroupCAInjector is the (opt-in) controller group for the CA injector controllers.
	// The group is pre-registered with all its members marked as ActivateExplicitly, so they are
	// excluded from the default activation set and only run when each controller is named
	// individually via the --controllers option (e.g. --controllers=cainjector-crd,...).
	// Naming the group itself (certcainjector) does not activate the explicit members due to a
	// limitation in the controller-manager-library.
	ControllerGroupCAInjector = "certcainjector"
	// DNSCluster is the name of the DNS cluster
	DNSCluster = "dns"
	// SourceCluster is the name of the source cluster
	SourceCluster = "source"
	// TargetCluster is the name of the target cluster
	TargetCluster = "target"
	// DefaultCluster is the name of the default cluster
	DefaultCluster = cluster.DEFAULT
)

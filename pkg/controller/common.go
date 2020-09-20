/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
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
	// DNSCluster is the name of the DNS cluster
	DNSCluster = "dns"
	// SourceCluster is the name of the source cluster
	SourceCluster = "source"
	// TargetCluster is the name of the target cluster
	TargetCluster = "target"
	// DefaultCluster is the name of the default cluster
	DefaultCluster = cluster.DEFAULT
)

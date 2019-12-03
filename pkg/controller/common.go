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

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

package main

import (
	"fmt"
	"os"

	"github.com/gardener/controller-manager-library/pkg/controllermanager"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/cluster"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/mappings"

	ctrl "github.com/gardener/cert-management/pkg/controller"
	_ "github.com/gardener/cert-management/pkg/controller/issuer"
	_ "github.com/gardener/cert-management/pkg/controller/source/ingress"
	_ "github.com/gardener/cert-management/pkg/controller/source/service"
)

var Version string

func init() {
	cluster.Configure(
		ctrl.TargetCluster,
		"target",
		"target cluster for certificates",
	).Fallback(ctrl.SourceCluster).MustRegister()

	cluster.Configure(
		ctrl.SourceCluster,
		"source",
		"source cluster to look for ingresses, services and own issuers",
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
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(Version)
		os.Exit(0)
	}
	controllermanager.Start("cert-controller-manager", "Certificate controller manager", "nothing")
}

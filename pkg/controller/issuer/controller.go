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

package issuer

import (
	"github.com/gardener/cert-management/pkg/cert/source"
	"github.com/gardener/cert-management/pkg/controller/issuer/core"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"time"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"

	"github.com/gardener/cert-management/pkg/apis/cert"
	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	crds "github.com/gardener/cert-management/pkg/cert"
	ctrl "github.com/gardener/cert-management/pkg/controller"
)

func init() {
	controller.Configure("issuer").
		DefaultedStringOption(core.OptDefaultIssuer, "default-issuer", "name of default issuer (from default cluster)").
		DefaultedStringOption(core.OptIssuerNamespace, "default", "namespace to lookup issuers on default cluster").
		StringOption(core.OptDefaultIssuerDomainRanges, "domain range restrictions when using default issuer separated by comma").
		StringOption(core.OptDNSNamespace, "namespace for creating challenge DNSEntries (in DNS cluster)").
		StringOption(core.OptDNSOwnerID, "ownerId for creating challenge DNSEntries").
		BoolOption(core.OptCascadeDelete, "If true, certificate secrets are deleted if dependent resources (certificate, ingress) are deleted").
		StringOption(source.OptClass, "Identifier used to differentiate responsible controllers for entries").
		DefaultedDurationOption(core.OptRenewalWindow, 30*24*time.Hour, "certificate is renewed if its validity period is shorter").
		FinalizerDomain(cert.GroupName).
		Cluster(ctrl.TargetCluster).
		CustomResourceDefinitions(crds.CertificateCRD).
		DefaultWorkerPool(2, 24*time.Hour).
		MainResource(api.GroupName, api.CertificateKind).
		Reconciler(newCompoundReconciler).
		Cluster(ctrl.DefaultCluster).
		CustomResourceDefinitions(crds.IssuerCRD).
		WorkerPool("issuers", 1, 0).
		SelectedWatch(selectIssuerNamespaceSelectionFunction, api.GroupName, api.IssuerKind).
		WorkerPool("secrets", 1, 0).
		SelectedWatch(selectIssuerNamespaceSelectionFunction, "core", "Secret").
		Cluster(ctrl.DNSCluster).
		MustRegister(ctrl.ControllerGroupCert)
}

func selectIssuerNamespaceSelectionFunction(c controller.Interface) (string, resources.TweakListOptionsFunc) {
	var options resources.TweakListOptionsFunc
	issuerNamespace, _ := c.GetStringOption(core.OptIssuerNamespace)
	return issuerNamespace, options
}

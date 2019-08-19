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

package certificate

import (
	"time"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"

	"github.com/gardener/cert-management/pkg/apis/cert"
	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	crds "github.com/gardener/cert-management/pkg/cert"
	ctrl "github.com/gardener/cert-management/pkg/controller"
)

const ControllerCertificate = "certificate"

//const FinalizerKey = cert.GroupName + "/" + ControllerCertificate

const (
	OptDefaultIssuer            = "default-issuer"
	OptIssuerNamespace          = "issuer-namespace"
	OptDNSNamespace             = "dns-namespace"
	OptDNSOwnerId               = "dns-owner-id"
	OptDefaultIssuerDomainRange = "default-issuer-domain-range"
	OptRenewalWindow            = "renewal-window"

	LabelCertificateHashKey = api.GroupName + "/certificate-hash"
	LabelCertificateKey     = api.GroupName + "/certificate"
	AnnotationNotAfter      = api.GroupName + "/not-after"
)

func init() {
	controller.Configure(ControllerCertificate).
		DefaultedStringOption(OptDefaultIssuer, "default-issuer", "name of default issuer (from default cluster)").
		DefaultedStringOption(OptIssuerNamespace, "default", "namespace to lookup issuers on default cluster").
		StringOption(OptDefaultIssuerDomainRange, "domain range restriction when using default issuer").
		StringOption(OptDNSNamespace, "namespace for creating challenge DNSEntries (in DNS cluster)").
		StringOption(OptDNSOwnerId, "ownerId for creating challenge DNSEntries").
		DefaultedDurationOption(OptRenewalWindow, 30*24*time.Hour, "certificate is renewed if its validity period is shorter").
		FinalizerDomain(cert.GroupName).
		Cluster(ctrl.TargetCluster).
		CustomResourceDefinitions(crds.CertificateCRD).
		DefaultWorkerPool(2, 24*time.Hour).
		MainResource(api.GroupName, api.CertificateKind).
		Reconciler(CertReconciler).
		Cluster(ctrl.DefaultCluster).
		CustomResourceDefinitions(crds.IssuerCRD).
		Cluster(ctrl.DNSCluster).
		MustRegister(ctrl.ControllerGroupCert)
}

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

package cert

import (
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"

	"github.com/gardener/controller-manager-library/pkg/resources/apiextensions"

	"github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
)

// IssuerCRD contains the standard columns for the issuer CRD.
var IssuerCRD = apiextensions.CreateCRDObjectWithStatus(v1alpha1.GroupName, v1alpha1.Version, v1alpha1.IssuerKind,
	v1alpha1.IssuerPlural, v1alpha1.IssuerShort, true,
	v1beta1.CustomResourceColumnDefinition{
		Name:        "SERVER",
		Description: "ACME Server",
		Type:        "string",
		JSONPath:    ".spec.acme.server",
	},
	v1beta1.CustomResourceColumnDefinition{
		Name:        "EMAIL",
		Description: "ACME Registration email",
		Type:        "string",
		JSONPath:    ".spec.acme.email",
	},
	v1beta1.CustomResourceColumnDefinition{
		Name:        "STATUS",
		Description: "Status of registration",
		Type:        "string",
		JSONPath:    ".status.state",
	},
	v1beta1.CustomResourceColumnDefinition{
		Name:        "TYPE",
		Description: "Issuer type",
		Type:        "string",
		JSONPath:    ".status.type",
	},
)

// CertificateCRD contains the standard columns for the certificate CRD.
var CertificateCRD = apiextensions.CreateCRDObjectWithStatus(v1alpha1.GroupName, v1alpha1.Version, v1alpha1.CertificateKind,
	v1alpha1.CertificatePlural, v1alpha1.CertificateShort, true,
	v1beta1.CustomResourceColumnDefinition{
		Name:        "COMMON NAME",
		Description: "Subject domain name of certificate",
		Type:        "string",
		JSONPath:    ".status.commonName",
	},
	v1beta1.CustomResourceColumnDefinition{
		Name:        "ISSUER",
		Description: "Issuer name",
		Type:        "string",
		JSONPath:    ".status.issuerRef.name",
	},
	v1beta1.CustomResourceColumnDefinition{
		Name:        "STATUS",
		Description: "Status of registration",
		Type:        "string",
		JSONPath:    ".status.state",
	},
	v1beta1.CustomResourceColumnDefinition{
		Name:        "EXPIRATION_DATE",
		Description: "Expiration date (not valid anymore after this date)",
		Type:        "string",
		JSONPath:    ".status.expirationDate",
		Priority:    500,
	},
	v1beta1.CustomResourceColumnDefinition{
		Name:        "DNS_NAMES",
		Description: "Domains names in subject alternative names",
		Type:        "string",
		JSONPath:    ".status.dnsNames",
		Priority:    2000,
	},
)

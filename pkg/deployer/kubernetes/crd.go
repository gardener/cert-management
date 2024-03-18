/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package kubernetes

import (
	_ "embed"
)

// CRDRevocations is the CustomResourceDefinition for CertificateRevocations.
//
//go:embed cert.gardener.cloud_certificaterevocations.yaml
var CRDRevocations string

// CRDCertificates is the CustomResourceDefinition for Certificates.
//
//go:embed cert.gardener.cloud_certificates.yaml
var CRDCertificates string

// CRDIssuers is the CustomResourceDefinition for Issuers.
//
//go:embed cert.gardener.cloud_issuers.yaml
var CRDIssuers string

/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package kubernetes

import (
	_ "embed"
	"fmt"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// CRDCertificateRevocations is the CustomResourceDefinition for CertificateRevocations.
//
//go:embed cert.gardener.cloud_certificaterevocations.yaml
var CRDCertificateRevocations string

// EmptyCRDRevocations returns the CRD for CertificateRevocations.
func EmptyCRDRevocations(codec runtime.Codec) (*apiextensionsv1.CustomResourceDefinition, error) {
	obj, err := runtime.Decode(codec, []byte(CRDCertificateRevocations))
	if err != nil {
		return nil, err
	}

	crd, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
	if !ok {
		return nil, fmt.Errorf("expected *apiextensionsv1.CustomResourceDefinition but got %T", obj)
	}

	return crd, nil
}

// CRDCertificates is the CustomResourceDefinition for Certificates.
//
//go:embed cert.gardener.cloud_certificates.yaml
var CRDCertificates string

// EmptyCRDCertificates returns the CRD for Certificates.
func EmptyCRDCertificates(codec runtime.Codec) (*apiextensionsv1.CustomResourceDefinition, error) {
	obj, err := runtime.Decode(codec, []byte(CRDCertificates))
	if err != nil {
		return nil, err
	}

	crd, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
	if !ok {
		return nil, fmt.Errorf("expected *apiextensionsv1.CustomResourceDefinition but got %T", obj)
	}

	return crd, nil
}

// CRDIssuers is the CustomResourceDefinition for Issuers.
//
//go:embed cert.gardener.cloud_issuers.yaml
var CRDIssuers string

// EmptyCRDIssuers returns the CRD for Issuers.
func EmptyCRDIssuers(codec runtime.Codec) (*apiextensionsv1.CustomResourceDefinition, error) {
	obj, err := runtime.Decode(codec, []byte(CRDIssuers))
	if err != nil {
		return nil, err
	}

	crd, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
	if !ok {
		return nil, fmt.Errorf("expected *apiextensionsv1.CustomResourceDefinition but got %T", obj)
	}

	return crd, nil
}

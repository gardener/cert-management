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

package ingress

import (
	"fmt"

	api "k8s.io/api/extensions/v1beta1"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"

	"github.com/gardener/cert-management/pkg/cert/source"
)

// CIngressSource is the ingress CertSource
type CIngressSource struct {
	source.DefaultCertSource
}

const (
	// AnnotationPurposeKey is the annotation key for the purpose
	AnnotationPurposeKey = "cert.gardener.cloud/purpose"
	// AnnotationPurposeValueManaged is the managed value for the purpose annotation
	AnnotationPurposeValueManaged = "managed"
	// DeprecatedLabelNamePurpose is the label key for the purpose
	DeprecatedLabelNamePurpose = "garden.sapcloud.io/purpose"
	// DeprecatedLabelValueManaged is the managed value for the purpose label
	DeprecatedLabelValueManaged = "managed-cert"
)

// NewIngressSource creates a CertSource
func NewIngressSource(_ controller.Interface) (source.CertSource, error) {
	return &CIngressSource{DefaultCertSource: source.DefaultCertSource{Events: map[resources.ClusterObjectKey]map[string]string{}}}, nil
}

// GetCertsInfo returns CertsInfo for the given object
func (s *CIngressSource) GetCertsInfo(logger logger.LogContext, obj resources.Object, current *source.CertCurrentState) (*source.CertsInfo, error) {
	info := s.NewCertsInfo(logger, obj)

	data := obj.Data().(*api.Ingress)
	annotValue, _ := resources.GetAnnotation(data, AnnotationPurposeKey)
	labelValue, _ := resources.GetLabel(data, DeprecatedLabelNamePurpose)
	managed := annotValue == AnnotationPurposeValueManaged || labelValue == DeprecatedLabelValueManaged
	if !managed || data.Spec.TLS == nil {
		return info, nil
	}

	var issuer *string
	annotatedIssuer, ok := resources.GetAnnotation(data, source.AnnotIssuer)
	if ok {
		issuer = &annotatedIssuer
	}
	var err error
	for _, tls := range data.Spec.TLS {
		if tls.SecretName == "" {
			err = fmt.Errorf("tls entry for hosts %s has no secretName", source.DomainsString(tls.Hosts))
			continue
		}
		info.Certs[tls.SecretName] = source.CertInfo{SecretName: tls.SecretName, Domains: tls.Hosts, IssuerName: issuer}
	}
	return info, err
}

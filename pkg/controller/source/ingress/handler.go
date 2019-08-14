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

type IngressSource struct {
	source.DefaultCertSource
}

const LabelNamePurpose = "garden.sapcloud.io/purpose"
const LabelValueManaged = "managed-cert"

func NewIngressSource(_ controller.Interface) (source.CertSource, error) {
	return &IngressSource{DefaultCertSource: source.DefaultCertSource{Events: map[resources.ClusterObjectKey]map[string]string{}}}, nil
}

func (this *IngressSource) GetCertsInfo(logger logger.LogContext, obj resources.Object, current *source.CertCurrentState) (*source.CertsInfo, error) {
	info := this.NewCertsInfo(logger, obj)

	data := obj.Data().(*api.Ingress)
	value, _ := resources.GetLabel(data, LabelNamePurpose)
	managed := value == LabelValueManaged
	if data.Spec.TLS == nil || !managed {
		return info, nil
	}

	var issuer *string
	annotatedIssuer, ok := resources.GetAnnotation(data, source.ANNOT_ISSUER)
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

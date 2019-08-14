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

package utils

import (
	"github.com/gardener/controller-manager-library/pkg/resources"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
)

var CertificateType = (*api.Certificate)(nil)

type CertificateObject struct {
	resources.Object
}

func (this *CertificateObject) Certificate() *api.Certificate {
	return this.Data().(*api.Certificate)
}

func Certificate(o resources.Object) *CertificateObject {

	if o.IsA(CertificateType) {
		return &CertificateObject{o}
	}
	return nil
}

func (this *CertificateObject) Spec() *api.CertificateSpec {
	return &this.Certificate().Spec
}
func (this *CertificateObject) Status() *api.CertificateStatus {
	return &this.Certificate().Status
}

func (this *CertificateObject) SafeCommonName() string {
	cn := this.Spec().CommonName
	if cn == nil {
		cn = this.Status().CommonName
	}
	if cn == nil {
		return ""
	}
	return *cn
}

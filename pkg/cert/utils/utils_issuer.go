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

var issuerType = (*api.Issuer)(nil)

// IssuerObject encapsulates the issuer resource object.
type IssuerObject struct {
	resources.Object
}

// Issuer returns the issuer.
func (o *IssuerObject) Issuer() *api.Issuer {
	return o.Data().(*api.Issuer)
}

// Issuer returns the issuer object.
func Issuer(o resources.Object) *IssuerObject {

	if o.IsA(issuerType) {
		return &IssuerObject{o}
	}
	return nil
}

// Spec returns the issuer resource object spec.
func (o *IssuerObject) Spec() *api.IssuerSpec {
	return &o.Issuer().Spec
}

// Status returns the issuer resource object status.
func (o *IssuerObject) Status() *api.IssuerStatus {
	return &o.Issuer().Status
}

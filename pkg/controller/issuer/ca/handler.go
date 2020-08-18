/*
 * Copyright 2019 SAP SE or an SAP affiliate company. All rights reserved. ur file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use ur file except in compliance with the License.
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

package ca

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/controller/issuer/core"
)

var caType = core.CAType

// NewCAIssuerHandler creates an ACME IssuerHandler.
func NewCAIssuerHandler(support *core.Support) (core.IssuerHandler, error) {
	return &caIssuerHandler{
		support: support,
	}, nil
}

type caIssuerHandler struct {
	support *core.Support
}

func (r *caIssuerHandler) Type() string {
	return core.CAType
}

func (r *caIssuerHandler) CanReconcile(issuer *api.Issuer) bool {
	return issuer != nil && issuer.Spec.CA != nil
}

func (r *caIssuerHandler) Reconcile(logger logger.LogContext, obj resources.Object, issuer *api.Issuer) reconcile.Status {
	logger.Infof("reconciling")

	ca := issuer.Spec.CA
	if ca == nil {
		return r.failedCA(logger, obj, api.StateError, fmt.Errorf("missing CA spec"))
	}

	r.support.RememberIssuerSecret(obj.ObjectName(), ca.PrivateKeySecretRef, "")

	var secret *corev1.Secret
	var err error
	if ca.PrivateKeySecretRef != nil {
		secret, err = r.support.ReadIssuerSecret(ca.PrivateKeySecretRef)
		if err != nil {
			return r.failedCA(logger, obj, api.StateError, fmt.Errorf("loading issuer secret failed with %s", err.Error()))
		}
		hash := r.support.CalcSecretHash(secret)
		r.support.RememberIssuerSecret(obj.ObjectName(), ca.PrivateKeySecretRef, hash)
	}
	if secret != nil && issuer.Status.CA != nil && issuer.Status.CA.Raw != nil {
		// TODO check secret?
		return r.support.SucceededAndTriggerCertificates(logger, obj, &caType, issuer.Status.CA.Raw)
	} else if secret != nil {
		// TODO check secret
		regRaw := []byte("{\"foo\":\"bar\"}")

		return r.support.SucceededAndTriggerCertificates(logger, obj, &caType, regRaw)
	} else {
		return r.failedCA(logger, obj, api.StateError, fmt.Errorf("`SecretRef` not provided"))
	}
}

func (r *caIssuerHandler) failedCA(logger logger.LogContext, obj resources.Object, state string, err error) reconcile.Status {
	return r.support.Failed(logger, obj, state, &caType, err)
}

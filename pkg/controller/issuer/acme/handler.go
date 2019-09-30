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

package acme

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/cert/legobridge"
	"github.com/gardener/cert-management/pkg/controller/issuer/core"
)

const ACMEType = "acme"

var acmeType = ACMEType

func NewACMEIssuerHandler(support *core.Support) (core.IssuerHandler, error) {
	return &acmeIssuerHandler{
		support: support,
	}, nil
}

type acmeIssuerHandler struct {
	support *core.Support
}

func (r *acmeIssuerHandler) Type() string {
	return ACMEType
}

func (r *acmeIssuerHandler) CanReconcile(issuer *api.Issuer) bool {
	return issuer != nil && issuer.Spec.ACME != nil
}

func (r *acmeIssuerHandler) Reconcile(logger logger.LogContext, obj resources.Object, issuer *api.Issuer) reconcile.Status {
	logger.Infof("reconciling")

	acme := issuer.Spec.ACME
	if acme == nil {
		return r.failedAcme(logger, obj, api.STATE_ERROR, fmt.Errorf("missing ACME spec"))
	}

	if acme.Email == "" {
		return r.failedAcme(logger, obj, api.STATE_ERROR, fmt.Errorf("missing email in ACME spec"))
	}
	if acme.Server == "" {
		return r.failedAcme(logger, obj, api.STATE_ERROR, fmt.Errorf("missing server in ACME spec"))
	}

	r.support.RememberIssuerSecret(obj.ObjectName(), issuer.Spec.ACME.PrivateKeySecretRef, "")

	var secret *corev1.Secret
	var err error
	if acme.PrivateKeySecretRef != nil {
		secret, err = r.support.ReadIssuerSecret(acme.PrivateKeySecretRef)
		if err != nil {
			if acme.AutoRegistration {
				logger.Info("spec.acme.privateKeySecretRef not existing, creating new account")
			} else {
				return r.failedAcme(logger, obj, api.STATE_ERROR, fmt.Errorf("loading issuer secret failed with %s", err.Error()))
			}
		}
		hash := r.support.CalcSecretHash(secret)
		r.support.RememberIssuerSecret(obj.ObjectName(), issuer.Spec.ACME.PrivateKeySecretRef, hash)
	}
	if secret != nil && issuer.Status.ACME != nil && issuer.Status.ACME.Raw != nil {
		user, err := legobridge.RegistrationUserFromSecretData(acme.Email, issuer.Status.ACME.Raw, secret.Data)
		if err != nil {
			return r.failedAcme(logger, obj, api.STATE_ERROR, fmt.Errorf("extracting registration user from secret failed with %s", err.Error()))
		}
		if user.Email != acme.Email {
			return r.failedAcme(logger, obj, api.STATE_ERROR, fmt.Errorf("email of registration user from secret does not match %s != %s", user.Email, acme.Email))
		}
		return r.support.SucceededAndTriggerCertificates(logger, obj, &acmeType, issuer.Status.ACME.Raw)
	} else if secret != nil || acme.AutoRegistration {
		var secretData map[string][]byte
		if secret != nil {
			secretData = secret.Data
		}
		user, err := legobridge.NewRegistrationUserFromEmail(acme.Email, acme.Server, secretData)
		if err != nil {
			return r.failedAcme(logger, obj, api.STATE_ERROR, fmt.Errorf("creating registration user failed with %s", err.Error()))
		}

		if secret != nil {
			err = r.support.UpdateIssuerSecret(issuer.ObjectMeta, user, secret)
			if err != nil {
				return r.failedAcme(logger, obj, api.STATE_ERROR, fmt.Errorf("updating issuer secret failed with %s", err.Error()))
			}
		} else {
			secretRef, secret, err := r.support.WriteIssuerSecretFromRegistrationUser(issuer.ObjectMeta, user, acme.PrivateKeySecretRef)
			if err != nil {
				return r.failedAcme(logger, obj, api.STATE_ERROR, fmt.Errorf("writing issuer secret failed with %s", err.Error()))
			}
			issuer.Spec.ACME.PrivateKeySecretRef = secretRef
			hash := r.support.CalcSecretHash(secret)
			r.support.RememberIssuerSecret(obj.ObjectName(), issuer.Spec.ACME.PrivateKeySecretRef, hash)
		}

		regRaw, err := user.RawRegistration()
		if err != nil {
			return r.failedAcme(logger, obj, api.STATE_ERROR, fmt.Errorf("registration marshalling failed with %s", err.Error()))
		}
		newObj, err := r.support.GetIssuerResources().Update(issuer)
		if err != nil {
			return r.failedAcme(logger, obj, api.STATE_ERROR, fmt.Errorf("updating resource failed with %s", err.Error()))
		}

		return r.support.SucceededAndTriggerCertificates(logger, newObj, &acmeType, regRaw)
	} else {
		return r.failedAcme(logger, obj, api.STATE_ERROR, fmt.Errorf("neither `SecretRef` or `AutoRegistration: true` provided"))
	}
}

func (r *acmeIssuerHandler) failedAcme(logger logger.LogContext, obj resources.Object, state string, err error) reconcile.Status {
	return r.support.Failed(logger, obj, state, &acmeType, err)
}

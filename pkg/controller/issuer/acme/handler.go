/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
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

var acmeType = core.ACMEType

// NewACMEIssuerHandler creates an ACME IssuerHandler.
func NewACMEIssuerHandler(support *core.Support) (core.IssuerHandler, error) {
	return &acmeIssuerHandler{
		support: support,
	}, nil
}

type acmeIssuerHandler struct {
	support *core.Support
}

func (r *acmeIssuerHandler) Type() string {
	return core.ACMEType
}

func (r *acmeIssuerHandler) CanReconcile(issuer *api.Issuer) bool {
	return issuer != nil && issuer.Spec.ACME != nil
}

func (r *acmeIssuerHandler) Reconcile(logger logger.LogContext, obj resources.Object, issuer *api.Issuer) reconcile.Status {
	logger.Infof("reconciling")

	acme := issuer.Spec.ACME
	if acme == nil {
		return r.failedAcme(logger, obj, api.StateError, fmt.Errorf("missing ACME spec"))
	}

	if acme.Email == "" {
		return r.failedAcme(logger, obj, api.StateError, fmt.Errorf("missing email in ACME spec"))
	}
	if acme.Server == "" {
		return r.failedAcme(logger, obj, api.StateError, fmt.Errorf("missing server in ACME spec"))
	}

	r.support.AddIssuerDomains(obj.ClusterKey(), issuer.Spec.ACME.Domains)

	r.support.RememberIssuerSecret(obj.ClusterKey(), issuer.Spec.ACME.PrivateKeySecretRef, "")

	issuerKey := r.support.ToIssuerKey(obj.ClusterKey())
	var secret *corev1.Secret
	var err error
	if acme.PrivateKeySecretRef != nil {
		secret, err = r.support.ReadIssuerSecret(issuerKey, acme.PrivateKeySecretRef)
		if err != nil {
			if acme.AutoRegistration {
				logger.Info("spec.acme.privateKeySecretRef not existing, creating new account")
			} else {
				return r.failedAcmeRetry(logger, obj, api.StateError, fmt.Errorf("loading issuer secret failed with %s", err.Error()))
			}
		}
		hash := r.support.CalcSecretHash(secret)
		r.support.RememberIssuerSecret(obj.ClusterKey(), issuer.Spec.ACME.PrivateKeySecretRef, hash)
	}
	if secret != nil && issuer.Status.ACME != nil && issuer.Status.ACME.Raw != nil {
		eabKeyID, eabHmacKey, err := r.support.LoadEABHmacKey(issuerKey, acme)
		if err != nil {
			return r.failedAcmeRetry(logger, obj, api.StateError, fmt.Errorf("loading EAB secret failed: %s", err))
		}
		user, err := legobridge.RegistrationUserFromSecretData(issuerKey, acme.Email, acme.Server, issuer.Status.ACME.Raw,
			secret.Data, eabKeyID, eabHmacKey)
		if err != nil {
			return r.failedAcmeRetry(logger, obj, api.StateError, fmt.Errorf("extracting registration user from secret failed with %s", err.Error()))
		}
		if user.GetEmail() != acme.Email {
			return r.failedAcme(logger, obj, api.StateError, fmt.Errorf("email of registration user from secret does not match %s != %s", user.GetEmail(), acme.Email))
		}
		return r.support.SucceededAndTriggerCertificates(logger, obj, &acmeType, issuer.Status.ACME.Raw)
	} else if secret != nil || acme.AutoRegistration {
		eabKid, eabHmacKey, err := r.prepareEAB(obj, issuer)
		if err != nil {
			return r.failedAcmeRetry(logger, obj, api.StateError, err)
		}
		var secretData map[string][]byte
		if secret != nil {
			secretData = secret.Data
		}
		user, err := legobridge.NewRegistrationUserFromEmail(issuerKey, acme.Email, acme.Server, secretData, eabKid, eabHmacKey)
		if err != nil {
			return r.failedAcmeRetry(logger, obj, api.StateError, fmt.Errorf("creating registration user failed with %s", err.Error()))
		}

		if secret != nil {
			err = r.support.UpdateIssuerSecret(issuerKey, user, secret)
			if err != nil {
				return r.failedAcmeRetry(logger, obj, api.StateError, fmt.Errorf("updating issuer secret failed with %s", err.Error()))
			}
		} else {
			secretRef, secret, err := r.support.WriteIssuerSecretFromRegistrationUser(issuerKey, issuer.UID, user, acme.PrivateKeySecretRef)
			if err != nil {
				return r.failedAcmeRetry(logger, obj, api.StateError, fmt.Errorf("writing issuer secret failed with %s", err.Error()))
			}
			issuer.Spec.ACME.PrivateKeySecretRef = secretRef
			hash := r.support.CalcSecretHash(secret)
			r.support.RememberIssuerSecret(obj.ClusterKey(), issuer.Spec.ACME.PrivateKeySecretRef, hash)
		}

		regRaw, err := user.RawRegistration()
		if err != nil {
			return r.failedAcme(logger, obj, api.StateError, fmt.Errorf("registration marshalling failed with %s", err.Error()))
		}
		newObj, err := r.support.GetIssuerResources(issuerKey).Update(issuer)
		if err != nil {
			return r.failedAcmeRetry(logger, obj, api.StateError, fmt.Errorf("updating resource failed with %s", err.Error()))
		}

		return r.support.SucceededAndTriggerCertificates(logger, newObj, &acmeType, regRaw)
	} else {
		return r.failedAcme(logger, obj, api.StateError, fmt.Errorf("neither `SecretRef` or `AutoRegistration: true` provided"))
	}
}

func (r *acmeIssuerHandler) prepareEAB(obj resources.Object, issuer *api.Issuer) (eabKid, eabHmacKey string, err error) {
	acme := issuer.Spec.ACME
	eab := acme.ExternalAccountBinding

	if eab == nil {
		return
	}

	r.support.RememberIssuerEABSecret(obj.ClusterKey(), eab.KeySecretRef, "")

	if eab.KeyID == "" {
		err = fmt.Errorf("missing keyID for external account binding in ACME spec")
		return
	}

	if eab.KeySecretRef == nil {
		err = fmt.Errorf("missing keySecretRef for external account binding in ACME spec")
		return
	}

	issuerKey := r.support.ToIssuerKey(obj.ClusterKey())
	secret, err := r.support.ReadIssuerSecret(issuerKey, eab.KeySecretRef)
	if err != nil {
		err = fmt.Errorf("loading issuer secret for external account binding failed with %s", err.Error())
		return
	}
	hash := r.support.CalcSecretHash(secret)
	r.support.RememberIssuerEABSecret(obj.ClusterKey(), eab.KeySecretRef, hash)

	hmacEncoded, ok := secret.Data[legobridge.KeyHmacKey]
	if !ok {
		err = fmt.Errorf("key %s not found in secret data", legobridge.KeyHmacKey)
		return
	}

	eabKid = eab.KeyID
	eabHmacKey = string(hmacEncoded)
	return
}

func (r *acmeIssuerHandler) failedAcme(logger logger.LogContext, obj resources.Object, state string, err error) reconcile.Status {
	return r.support.Failed(logger, obj, state, &acmeType, err, false)
}

func (r *acmeIssuerHandler) failedAcmeRetry(logger logger.LogContext, obj resources.Object, state string, err error) reconcile.Status {
	return r.support.Failed(logger, obj, state, &acmeType, err, true)
}

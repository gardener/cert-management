/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package ca

import (
	"fmt"
	"math"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/cert/legobridge"
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

	issuer.Spec.RequestsPerDayQuota = ptr.To(math.MaxInt64)

	r.support.RememberIssuerSecret(obj.ClusterKey(), ca.PrivateKeySecretRef, "")

	var secret *corev1.Secret
	var err error
	if ca.PrivateKeySecretRef != nil {
		issuerKey := r.support.ToIssuerKey(obj.ClusterKey())
		secret, err = r.support.ReadIssuerSecret(issuerKey, ca.PrivateKeySecretRef)
		if err != nil {
			return r.failedCARetry(logger, obj, api.StateError, fmt.Errorf("loading issuer secret failed: %w", err))
		}
		hash := r.support.CalcSecretHash(secret)
		r.support.RememberIssuerSecret(obj.ClusterKey(), ca.PrivateKeySecretRef, hash)
	}
	if secret != nil && issuer.Status.CA != nil && issuer.Status.CA.Raw != nil {
		_, err := validateSecretCA(secret)
		if err != nil {
			return r.failedCA(logger, obj, api.StateError, err)
		}
		return r.support.SucceededAndTriggerCertificates(logger, obj, &caType, issuer.Status.CA.Raw)
	} else if secret != nil {
		CAInfoRaw, err := validateSecretCA(secret)
		if err != nil {
			return r.failedCA(logger, obj, api.StateError, err)
		}
		return r.support.SucceededAndTriggerCertificates(logger, obj, &caType, CAInfoRaw)
	} else {
		return r.failedCA(logger, obj, api.StateError, fmt.Errorf("`SecretRef` not provided"))
	}
}

func validateSecretCA(secret *corev1.Secret) ([]byte, error) {
	// Validate correct type
	if secret.Type != corev1.SecretTypeTLS {
		return nil, fmt.Errorf("Secret is not of type %s", corev1.SecretTypeTLS)
	}

	// Validate it can be used as a CAKeyPair
	CAKeyPair, err := legobridge.CAKeyPairFromSecretData(secret.Data)
	if err != nil {
		return nil, fmt.Errorf("extracting CA Keypair from secret failed: %w", err)
	}

	// Validate cert and key are valid and that they match together
	ok, err := legobridge.ValidatePublicKeyWithPrivateKey(CAKeyPair.Cert.PublicKey, CAKeyPair.Key)
	if err != nil {
		return nil, fmt.Errorf("check private key failed: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("private key does not match certificate")
	}

	// Check if certificate is a CA
	if !legobridge.IsCertCA(CAKeyPair.Cert) {
		return nil, fmt.Errorf("certificate is not a CA")
	}

	// Check expiration
	if legobridge.IsCertExpired(CAKeyPair.Cert) {
		return nil, fmt.Errorf("certificate is expired")
	}

	CAInfoRaw, err := CAKeyPair.RawCertInfo()
	if err != nil {
		return nil, fmt.Errorf("cert info marshalling failed: %w", err)
	}

	return CAInfoRaw, nil
}

func (r *caIssuerHandler) failedCA(logger logger.LogContext, obj resources.Object, state string, err error) reconcile.Status {
	return r.support.Failed(logger, obj, state, &caType, err, false)
}

func (r *caIssuerHandler) failedCARetry(logger logger.LogContext, obj resources.Object, state string, err error) reconcile.Status {
	return r.support.Failed(logger, obj, state, &caType, err, true)
}

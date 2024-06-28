/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package selfSigned

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

var selfSignedType = core.SelfSignedType

// NewSelfSignedIssuerHandler creates an SelfSigned IssuerHandler.
func NewSelfSignedIssuerHandler(support *core.Support) (core.IssuerHandler, error) {
	return &selfSignedIssuerHandler{
		support: support,
	}, nil
}

type selfSignedIssuerHandler struct {
	support *core.Support
}

func (h *selfSignedIssuerHandler) Type() string {
	return core.SelfSignedType
}

func (h *selfSignedIssuerHandler) CanReconcile(issuer *api.Issuer) bool {
	return issuer != nil && issuer.Spec.SelfSigned != nil
}

func (h *selfSignedIssuerHandler) Reconcile(logger logger.LogContext, obj resources.Object, issuer *api.Issuer) reconcile.Status {
	logger.Infof("reconciling")

	selfSigned := issuer.Spec.SelfSigned
	if selfSigned == nil {
		return h.support.Failed(logger, obj, api.StateError, &selfSignedType, fmt.Errorf("missing selfSigned spec"), false)
	}
	return h.support.SucceedSelfSignedIssuer(logger, obj, &selfSignedType, issuer.Status.Type)
}

func validateSecretCA(secret *corev1.Secret) ([]byte, error) {
	// Validate correct type
	if secret.Type != corev1.SecretTypeTLS {
		return nil, fmt.Errorf("Secret is not if type %s", corev1.SecretTypeTLS)
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

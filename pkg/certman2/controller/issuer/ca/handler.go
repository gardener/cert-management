/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package ca

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/cert-management/pkg/cert/legobridge"
	"github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/certman2/core"
)

// NewCAIssuerHandler creates an ACME IssuerHandler.
func NewCAIssuerHandler(client client.Client, support *core.Support, secondary bool) (core.IssuerHandler, error) {
	return &caIssuerHandler{
		client:    client,
		support:   support,
		secondary: secondary,
	}, nil
}

type caIssuerHandler struct {
	support   *core.Support
	client    client.Client
	secondary bool
}

func (h *caIssuerHandler) Type() string {
	return core.CAType
}

func (h *caIssuerHandler) CanReconcile(issuer *v1alpha1.Issuer) bool {
	return issuer != nil && issuer.Spec.CA != nil
}

func (h *caIssuerHandler) Reconcile(ctx context.Context, log logr.Logger, issuer *v1alpha1.Issuer) (reconcile.Result, error) {
	log.Info("reconciling")

	ca := issuer.Spec.CA
	issuerKey := h.issuerKey(issuer)
	h.support.RememberIssuerSecret(issuerKey, ca.PrivateKeySecretRef, "")

	var secret *corev1.Secret
	if ca.PrivateKeySecretRef != nil {
		secret = &corev1.Secret{}
		if err := h.client.Get(ctx, core.ObjectKeyFromSecretReference(ca.PrivateKeySecretRef), secret); err != nil {
			return h.failedCARetry(ctx, issuer, v1alpha1.StateError, fmt.Errorf("loading issuer secret failed: %w", err))
		}
		hash := h.support.CalcSecretHash(secret)
		h.support.RememberIssuerSecret(issuerKey, ca.PrivateKeySecretRef, hash)
	}
	if secret != nil {
		caInfoRaw, err := validateSecretCA(secret)
		if err != nil {
			return h.failedCA(ctx, issuer, v1alpha1.StateError, err)
		}
		return h.succeededAndTriggerCertificates(ctx, issuer, caInfoRaw)
	} else {
		return h.failedCA(ctx, issuer, v1alpha1.StateError, fmt.Errorf("`SecretRef` not provided"))
	}
}

func (h *caIssuerHandler) Delete(ctx context.Context, log logr.Logger, issuer *v1alpha1.Issuer) (reconcile.Result, error) {
	issuerKey := h.issuerKey(issuer)
	h.support.RemoveIssuer(issuerKey)
	log.Info("deleted")
	return reconcile.Result{}, nil
}

func (h *caIssuerHandler) failedCA(ctx context.Context, issuer *v1alpha1.Issuer, state string, err error) (reconcile.Result, error) {
	if err2 := h.updateStatusFailed(ctx, issuer, state, err); err2 != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}

func (h *caIssuerHandler) failedCARetry(ctx context.Context, issuer *v1alpha1.Issuer, state string, err error) (reconcile.Result, error) {
	if err2 := h.updateStatusFailed(ctx, issuer, state, err); err != nil {
		return reconcile.Result{}, errors.Join(err, err2)
	}
	return reconcile.Result{}, err
}

func (h *caIssuerHandler) issuerKey(issuer *v1alpha1.Issuer) core.IssuerKey {
	return core.NewIssuerKey(client.ObjectKeyFromObject(issuer), h.secondary)
}

func (h *caIssuerHandler) succeededAndTriggerCertificates(ctx context.Context, issuer *v1alpha1.Issuer, caInfoRaw []byte) (reconcile.Result, error) {
	// TODO
	/*
		s.reportAllCertificateMetrics()
		s.triggerCertificates(logger, s.ToIssuerKey(obj.ClusterKey()))
	*/
	if err := h.updateStatusSucceeded(ctx, issuer, caInfoRaw); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}

func (h *caIssuerHandler) updateStatusFailed(ctx context.Context, issuer *v1alpha1.Issuer, state string, err error) error {
	patch := client.MergeFrom(issuer.DeepCopy())
	issuer.Status.Message = ptr.To(err.Error())
	issuer.Status.Type = ptr.To(core.CAType)
	issuer.Status.State = state
	issuer.Status.ObservedGeneration = issuer.Generation
	issuer.Status.RequestsPerDayQuota = h.support.RememberIssuerQuotas(h.issuerKey(issuer), issuer.Spec.RequestsPerDayQuota)
	issuer.Status.ACME = nil
	issuer.Status.CA = nil

	return h.client.Status().Patch(ctx, issuer, patch)
}

func (h *caIssuerHandler) updateStatusSucceeded(ctx context.Context, issuer *v1alpha1.Issuer, caInfoRaw []byte) error {
	patch := client.MergeFrom(issuer.DeepCopy())
	issuer.Status.Message = nil
	issuer.Status.Type = ptr.To(core.CAType)
	issuer.Status.State = v1alpha1.StateReady
	issuer.Status.ObservedGeneration = issuer.Generation
	issuer.Status.RequestsPerDayQuota = h.support.RememberIssuerQuotas(h.issuerKey(issuer), issuer.Spec.RequestsPerDayQuota)
	issuer.Status.ACME = nil
	issuer.Status.CA = &runtime.RawExtension{Raw: caInfoRaw}
	return h.client.Status().Patch(ctx, issuer, patch)
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

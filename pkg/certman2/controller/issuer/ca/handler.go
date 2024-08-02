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

func (r *caIssuerHandler) Type() string {
	return core.CAType
}

func (r *caIssuerHandler) CanReconcile(issuer *v1alpha1.Issuer) bool {
	return issuer != nil && issuer.Spec.CA != nil
}

func (r *caIssuerHandler) Reconcile(ctx context.Context, log logr.Logger, issuer *v1alpha1.Issuer) (reconcile.Result, error) {
	log.Info("reconciling")

	ca := issuer.Spec.CA
	if ca == nil {
		return r.failedCA(ctx, issuer, v1alpha1.StateError, fmt.Errorf("missing CA spec"))
	}

	issuerKey := r.issuerKey(issuer)
	r.support.RememberIssuerSecret(issuerKey, ca.PrivateKeySecretRef, "")

	var secret *corev1.Secret
	if ca.PrivateKeySecretRef != nil {
		secret = &corev1.Secret{}
		if err := r.client.Get(ctx, core.ObjectKeyFromSecretReference(ca.PrivateKeySecretRef), secret); err != nil {
			return r.failedCARetry(ctx, issuer, v1alpha1.StateError, fmt.Errorf("loading issuer secret failed: %w", err))
		}
		hash := r.support.CalcSecretHash(secret)
		r.support.RememberIssuerSecret(issuerKey, ca.PrivateKeySecretRef, hash)
	}
	if secret != nil {
		caInfoRaw, err := validateSecretCA(secret)
		if err != nil {
			return r.failedCA(ctx, issuer, v1alpha1.StateError, err)
		}
		return r.succeededAndTriggerCertificates(ctx, issuer, caInfoRaw)
	} else {
		return r.failedCA(ctx, issuer, v1alpha1.StateError, fmt.Errorf("`SecretRef` not provided"))
	}
}

func (r *caIssuerHandler) Delete(ctx context.Context, log logr.Logger, issuer *v1alpha1.Issuer) (reconcile.Result, error) {
	issuerKey := r.issuerKey(issuer)
	r.support.RemoveIssuer(issuerKey)
	log.Info("deleted")
	return reconcile.Result{}, nil
}

func (r *caIssuerHandler) failedCA(ctx context.Context, issuer *v1alpha1.Issuer, state string, err error) (reconcile.Result, error) {
	if err2 := r.updateStatusFailed(ctx, issuer, state, err); err2 != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func (r *caIssuerHandler) failedCARetry(ctx context.Context, issuer *v1alpha1.Issuer, state string, err error) (reconcile.Result, error) {
	if err2 := r.updateStatusFailed(ctx, issuer, state, err); err != nil {
		return reconcile.Result{}, errors.Join(err, err2)
	}

	return reconcile.Result{}, err
}

func (r *caIssuerHandler) issuerKey(issuer *v1alpha1.Issuer) core.IssuerKey {
	return core.NewIssuerKey(client.ObjectKeyFromObject(issuer), r.secondary)
}

func (r *caIssuerHandler) succeededAndTriggerCertificates(ctx context.Context, issuer *v1alpha1.Issuer, caInfoRaw []byte) (reconcile.Result, error) {
	// TODO
	/*
		s.reportAllCertificateMetrics()
		s.triggerCertificates(logger, s.ToIssuerKey(obj.ClusterKey()))
	*/
	if err := r.updateStatusSucceeded(ctx, issuer, caInfoRaw); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}

func (r *caIssuerHandler) updateStatusFailed(ctx context.Context, issuer *v1alpha1.Issuer, state string, err error) error {
	patch := client.MergeFrom(issuer.DeepCopy())
	issuer.Status.Message = ptr.To(err.Error())
	issuer.Status.Type = ptr.To(core.CAType)
	issuer.Status.State = state
	issuer.Status.ObservedGeneration = issuer.Generation
	issuer.Status.RequestsPerDayQuota = r.support.RememberIssuerQuotas(r.issuerKey(issuer), issuer.Spec.RequestsPerDayQuota)
	issuer.Status.ACME = nil
	issuer.Status.CA = nil

	return r.client.Status().Patch(ctx, issuer, patch)
}

func (r *caIssuerHandler) updateStatusSucceeded(ctx context.Context, issuer *v1alpha1.Issuer, caInfoRaw []byte) error {
	patch := client.MergeFrom(issuer.DeepCopy())
	issuer.Status.Message = nil
	issuer.Status.Type = ptr.To(core.CAType)
	issuer.Status.State = v1alpha1.StateReady
	issuer.Status.ObservedGeneration = issuer.Generation
	issuer.Status.RequestsPerDayQuota = r.support.RememberIssuerQuotas(r.issuerKey(issuer), issuer.Spec.RequestsPerDayQuota)
	issuer.Status.ACME = nil
	issuer.Status.CA = &runtime.RawExtension{Raw: caInfoRaw}
	return r.client.Status().Patch(ctx, issuer, patch)
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

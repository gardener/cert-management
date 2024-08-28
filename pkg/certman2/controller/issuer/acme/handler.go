/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package acme

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gardener/cert-management/pkg/cert/legobridge"
	"github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/certman2/core"
)

// NewACMEIssuerHandler creates an ACME IssuerHandler.
func NewACMEIssuerHandler(client client.Client, support *core.Support, secondary bool) (core.IssuerHandler, error) {
	return &acmeIssuerHandler{
		client:    client,
		support:   support,
		secondary: secondary,
	}, nil
}

type acmeIssuerHandler struct {
	support   *core.Support
	client    client.Client
	secondary bool
}

func (h *acmeIssuerHandler) Type() string {
	return core.ACMEType
}

func (h *acmeIssuerHandler) CanReconcile(issuer *v1alpha1.Issuer) bool {
	return issuer != nil && issuer.Spec.ACME != nil
}

func (h *acmeIssuerHandler) Reconcile(ctx context.Context, log logr.Logger, issuer *v1alpha1.Issuer) (reconcile.Result, error) {
	log.Info("reconciling")
	issuerKey := h.issuerKey(issuer)
	acme := issuer.Spec.ACME

	if acme.Email == "" {
		return h.failedAcme(ctx, issuer, v1alpha1.StateError, fmt.Errorf("missing email in ACME spec"))
	}
	if acme.Server == "" {
		return h.failedAcme(ctx, issuer, v1alpha1.StateError, fmt.Errorf("missing server in ACME spec"))
	}

	h.support.AddIssuerDomains(issuerKey, acme.Domains)
	h.support.RememberIssuerSecret(issuerKey, acme.PrivateKeySecretRef, "")

	var secret *corev1.Secret
	var secretHash string
	var err error
	if acme.PrivateKeySecretRef != nil {
		secret = &corev1.Secret{}
		if err := h.client.Get(ctx, core.ObjectKeyFromSecretReference(acme.PrivateKeySecretRef), secret); err != nil {
			if !acme.AutoRegistration {
				return h.failedAcmeRetry(ctx, issuer, v1alpha1.StateError, fmt.Errorf("loading issuer secret failed: %w", err))
			}
			secret = nil
			log.Info("spec.acme.privateKeySecretRef not existing, creating new account")
		}
		secretHash = h.support.CalcSecretHash(secret)
		h.support.RememberIssuerSecret(issuerKey, acme.PrivateKeySecretRef, secretHash)
	}
	eabKeyID, eabHmacKey, err := h.support.LoadEABHmacKey(ctx, h.client, issuerKey, acme)
	if err != nil {
		return h.failedAcmeRetry(ctx, issuer, v1alpha1.StateError, fmt.Errorf("loading EAB secret failed: %w", err))
	}

	var rawReg []byte
	if secret != nil {
		if core.IsSameExistingRegistration(issuer.Status.ACME, secretHash) {
			rawReg = issuer.Status.ACME.Raw
		} else {
			user, err := legobridge.NewRegistrationUserFromEmail(issuerKey, acme.Email, acme.Server, secret.Data, eabKeyID, eabHmacKey)
			if err != nil {
				return h.failedAcmeRetry(ctx, issuer, v1alpha1.StateError, fmt.Errorf("creating registration user failed: %w", err))
			}
			rawReg, err = user.RawRegistration()
			if err != nil {
				return h.failedAcme(ctx, issuer, v1alpha1.StateError, fmt.Errorf("registration marshalling failed: %w", err))
			}
		}
		user, err := legobridge.RegistrationUserFromSecretData(issuerKey, acme.Email, acme.Server, rawReg,
			secret.Data, eabKeyID, eabHmacKey)
		if err != nil {
			return h.failedAcmeRetry(ctx, issuer, v1alpha1.StateError, fmt.Errorf("extracting registration user from secret failed: %w", err))
		}
		if user.GetEmail() != acme.Email {
			return h.failedAcme(ctx, issuer, v1alpha1.StateError, fmt.Errorf("email of registration user from secret does not match %s != %s", user.GetEmail(), acme.Email))
		}
		rawReg, err = core.WrapRegistration(rawReg, secretHash)
		if err != nil {
			return h.failedAcme(ctx, issuer, v1alpha1.StateError, fmt.Errorf("wrapped registration marshalling failed: %w", err))
		}
		return h.SucceededAndTriggerCertificates(ctx, issuer, rawReg)
	} else if acme.AutoRegistration {
		user, err := legobridge.NewRegistrationUserFromEmail(issuerKey, acme.Email, acme.Server, nil, eabKeyID, eabHmacKey)
		if err != nil {
			return h.failedAcmeRetry(ctx, issuer, v1alpha1.StateError, fmt.Errorf("creating registration user failed: %w", err))
		}
		secretRef, secret, err := h.WriteIssuerSecretFromRegistrationUser(ctx, issuerKey, issuer, user, acme.PrivateKeySecretRef)
		if err != nil {
			return h.failedAcmeRetry(ctx, issuer, v1alpha1.StateError, fmt.Errorf("writing issuer secret failed: %w", err))
		}
		acme.PrivateKeySecretRef = secretRef
		secretHash = h.support.CalcSecretHash(secret)
		h.support.RememberIssuerSecret(issuerKey, acme.PrivateKeySecretRef, secretHash)

		rawReg, err = user.RawRegistration()
		if err != nil {
			return h.failedAcme(ctx, issuer, v1alpha1.StateError, fmt.Errorf("registration marshalling failed: %w", err))
		}

		err = h.client.Update(ctx, issuer)
		if err != nil {
			return h.failedAcmeRetry(ctx, issuer, v1alpha1.StateError, fmt.Errorf("updating issuer resource failed: %w", err))
		}

		rawReg, err := core.WrapRegistration(rawReg, secretHash)
		if err != nil {
			return h.failedAcme(ctx, issuer, v1alpha1.StateError, fmt.Errorf("wrapped registration marshalling failed: %w", err))
		}
		return h.SucceededAndTriggerCertificates(ctx, issuer, rawReg)
	} else {
		return h.failedAcme(ctx, issuer, v1alpha1.StateError, fmt.Errorf("neither `SecretRef` or `AutoRegistration: true` provided"))
	}
}

func (h *acmeIssuerHandler) Delete(_ context.Context, log logr.Logger, issuer *v1alpha1.Issuer) (reconcile.Result, error) {
	issuerKey := h.issuerKey(issuer)
	h.support.RemoveIssuer(issuerKey)
	log.Info("deleted")
	return reconcile.Result{}, nil
}

func (h *acmeIssuerHandler) failedAcme(ctx context.Context, issuer *v1alpha1.Issuer, state string, err error) (reconcile.Result, error) {
	if err2 := h.updateStatusFailed(ctx, issuer, state, err); err2 != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}

func (h *acmeIssuerHandler) failedAcmeRetry(ctx context.Context, issuer *v1alpha1.Issuer, state string, err error) (reconcile.Result, error) {
	if err2 := h.updateStatusFailed(ctx, issuer, state, err); err2 != nil {
		return reconcile.Result{}, errors.Join(err, err2)
	}
	return reconcile.Result{}, err
}

func (h *acmeIssuerHandler) issuerKey(issuer *v1alpha1.Issuer) core.IssuerKey {
	return core.NewIssuerKey(client.ObjectKeyFromObject(issuer), h.secondary)
}

func (h *acmeIssuerHandler) updateStatusFailed(ctx context.Context, issuer *v1alpha1.Issuer, state string, err error) error {
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

func (h *acmeIssuerHandler) updateStatusSucceeded(ctx context.Context, issuer *v1alpha1.Issuer, rawReg []byte) error {
	patch := client.MergeFrom(issuer.DeepCopy())
	issuer.Status.Message = nil
	issuer.Status.Type = ptr.To(core.ACMEType)
	issuer.Status.State = v1alpha1.StateReady
	issuer.Status.ObservedGeneration = issuer.Generation
	issuer.Status.RequestsPerDayQuota = h.support.RememberIssuerQuotas(h.issuerKey(issuer), issuer.Spec.RequestsPerDayQuota)
	issuer.Status.ACME = &runtime.RawExtension{Raw: rawReg}
	issuer.Status.CA = nil
	return h.client.Status().Patch(ctx, issuer, patch)
}

func (h *acmeIssuerHandler) SucceededAndTriggerCertificates(ctx context.Context, issuer *v1alpha1.Issuer, rawReg []byte) (reconcile.Result, error) {
	// TODO
	/*
		reportAllCertificateMetrics()
		triggerCertificatesReconciliation()
	*/
	if err := h.updateStatusSucceeded(ctx, issuer, rawReg); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}

// WriteIssuerSecretFromRegistrationUser writes an issuer secret
func (h *acmeIssuerHandler) WriteIssuerSecretFromRegistrationUser(
	ctx context.Context,
	issuerKey core.IssuerKey,
	issuer *v1alpha1.Issuer,
	reguser *legobridge.RegistrationUser,
	secretRef *corev1.SecretReference,
) (*corev1.SecretReference, *corev1.Secret, error) {
	var err error
	secret := &corev1.Secret{}
	if secretRef != nil && secretRef.Name != "" {
		secret.SetName(secretRef.Name)
		secret.SetNamespace(core.NormalizeNamespace(secretRef.Namespace))
	} else {
		secret.SetGenerateName(issuerKey.Name() + "-")
		secret.SetNamespace(core.NormalizeNamespace(issuerKey.Namespace()))
	}
	secret.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: v1alpha1.Version, Kind: v1alpha1.IssuerKind, Name: issuerKey.Name(), UID: issuer.UID}})
	secret.Data, err = reguser.ToSecretData()
	if err != nil {
		return nil, nil, err
	}
	if err := h.client.Create(ctx, secret); err != nil {
		return nil, nil, err
	}
	return &corev1.SecretReference{Name: secret.Name, Namespace: secret.Namespace}, secret, nil
}

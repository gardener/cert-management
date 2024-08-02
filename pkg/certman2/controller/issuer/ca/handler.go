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

	"github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/cert/legobridge"
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
		secret := &corev1.Secret{}
		if err := r.client.Get(ctx, core.ObjectKeyFromSecretReference(ca.PrivateKeySecretRef), secret); err != nil {
			return r.failedCARetry(ctx, issuer, v1alpha1.StateError, fmt.Errorf("loading issuer secret failed: %w", err))
		}
		hash := r.support.CalcSecretHash(secret)
		r.support.RememberIssuerSecret(issuerKey, ca.PrivateKeySecretRef, hash)
	}
	if secret != nil && issuer.Status.CA != nil && issuer.Status.CA.Raw != nil {
		_, err := validateSecretCA(secret)
		if err != nil {
			return r.failedCA(ctx, issuer, v1alpha1.StateError, err)
		}
		return r.succeededAndTriggerCertificates(ctx, issuer, issuer.Status.CA.Raw)
	} else if secret != nil {
		CAInfoRaw, err := validateSecretCA(secret)
		if err != nil {
			return r.failedCA(ctx, issuer, v1alpha1.StateError, err)
		}
		return r.succeededAndTriggerCertificates(ctx, issuer, CAInfoRaw)
	} else {
		return r.failedCA(ctx, issuer, v1alpha1.StateError, fmt.Errorf("`SecretRef` not provided"))
	}
}

func (r *caIssuerHandler) Delete(ctx context.Context, log logr.Logger, issuer *v1alpha1.Issuer) (reconcile.Result, error) {
	issuerKey := core.NewIssuerKey(client.ObjectKeyFromObject(issuer), r.secondary)
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

/*
func (s *Support) prepareUpdateStatus(obj resources.Object, state string, itype *string, msg *string) (*resources.ModificationState, *api.IssuerStatus) {
	issuer := obj.Data().(*api.Issuer)
	status := &issuer.Status

	mod := resources.NewModificationState(obj)
	mod.AssureStringPtrPtr(&status.Message, msg)
	mod.AssureStringPtrPtr(&status.Type, itype)
	mod.AssureStringValue(&status.State, state)
	mod.AssureInt64Value(&status.ObservedGeneration, obj.GetGeneration())
	mod.AssureIntValue(&status.RequestsPerDayQuota, s.RememberIssuerQuotas(obj.ClusterKey(), issuer.Spec.RequestsPerDayQuota))

	return mod, status
}


func (s *Support) updateStatus(mod *resources.ModificationState) {
	err := mod.UpdateStatus()
	if err != nil {
		logger.Warnf("updating status failed with: %s", err)
	}
}

// Failed handles failed.
func (s *Support) Failed(logger logger.LogContext, obj resources.Object, state string, itype *string, err error, retry bool) reconcile.Status {
	msg := err.Error()

	mod, _ := s.prepareUpdateStatus(obj, state, itype, &msg)
	s.updateStatus(mod)

	if retry {
		return reconcile.Delay(logger, err)
	}
	return reconcile.Failed(logger, err)
}

// SucceededAndTriggerCertificates handles succeeded and trigger certificates.
func (s *Support) SucceededAndTriggerCertificates(logger logger.LogContext, obj resources.Object, itype *string, regRaw []byte) reconcile.Status {
	s.RememberIssuerQuotas(obj.ClusterKey(), obj.Data().(*api.Issuer).Spec.RequestsPerDayQuota)

	s.reportAllCertificateMetrics()
	s.triggerCertificates(logger, s.ToIssuerKey(obj.ClusterKey()))

	mod, status := s.prepareUpdateStatus(obj, api.StateReady, itype, nil)
	if itype != nil {
		switch *itype {
		case ACMEType:
			updateTypeStatus(mod, &status.ACME, regRaw)
		case CAType:
			updateTypeStatus(mod, &status.CA, regRaw)
		}
	}
	s.updateStatus(mod)

	return reconcile.Succeeded(logger)
}
*/

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

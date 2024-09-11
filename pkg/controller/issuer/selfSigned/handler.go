/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package selfSigned

import (
	"fmt"
	"math"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
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
	maxInt := math.MaxInt64
	issuer.Spec.RequestsPerDayQuota = &maxInt

	return h.support.SucceedSelfSignedIssuer(logger, obj, &selfSignedType)
}

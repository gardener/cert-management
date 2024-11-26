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
	"k8s.io/utils/ptr"

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
	issuer.Spec.RequestsPerDayQuota = ptr.To(math.MaxInt64)

	return h.support.SucceedSelfSignedIssuer(logger, obj, &selfSignedType)
}

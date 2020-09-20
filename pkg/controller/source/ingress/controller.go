/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package ingress

import (
	"github.com/gardener/controller-manager-library/pkg/resources"

	"github.com/gardener/cert-management/pkg/cert/source"
	ctrl "github.com/gardener/cert-management/pkg/controller"
)

var mainResource = resources.NewGroupKind("extensions", "Ingress")

func init() {
	source.CertSourceController(source.NewCertSourceTypeForCreator("ingress-cert", mainResource, NewIngressSource), nil).
		FinalizerDomain("cert.gardener.cloud").
		RequireLease(ctrl.SourceCluster).
		MustRegister(ctrl.ControllerGroupSource)
}

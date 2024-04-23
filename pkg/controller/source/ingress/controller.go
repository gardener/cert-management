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

// MainResource is the GroupKind for the ingress resource.
var MainResource = resources.NewGroupKind("networking.k8s.io", "Ingress")

func init() {
	source.CertSourceController(source.NewCertSourceTypeForCreator("ingress-cert", MainResource, NewIngressSource), nil).
		FinalizerDomain("cert.gardener.cloud").
		RequireLease(ctrl.SourceCluster).
		MustRegister(ctrl.ControllerGroupSource)
}

// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package gatewayapi

import (
	"strings"

	ctrl "github.com/gardener/cert-management/pkg/controller"
	"github.com/gardener/controller-manager-library/pkg/resources"

	"github.com/gardener/cert-management/pkg/cert/source"
)

// Group is the group of the Gateway API.
const Group = "gateway.networking.k8s.io"

var (
	// GroupKindGateway is the GroupKind for the Gateway resource.
	GroupKindGateway = resources.NewGroupKind(Group, "Gateway")
	// GroupKindHTTPRoute is the GroupKind for the HTTPRoute resource.
	GroupKindHTTPRoute = resources.NewGroupKind(Group, "HTTPRoute")
)

func init() {
	source.CertSourceController(source.NewCertSourceTypeForCreator("k8s-gateways-dns", GroupKindGateway, NewGatewaySource), nil).
		FinalizerDomain("cert.gardener.cloud").
		RequireLease(ctrl.SourceCluster).
		DeactivateOnCreationErrorCheck(deactivateOnMissingMainResource).
		Reconciler(httpRoutesReconciler, "httproutes").
		WorkerPool("httproutes", 2, 0).
		ReconcilerWatchesByGK("httproutes", GroupKindHTTPRoute).
		MustRegister(ctrl.ControllerGroupSource)
}

func deactivateOnMissingMainResource(err error) bool {
	return strings.Contains(err.Error(), "gardener/cml/resources/UNKNOWN_RESOURCE") &&
		(strings.Contains(err.Error(), GroupKindGateway.String()) || strings.Contains(err.Error(), GroupKindHTTPRoute.String()))
}

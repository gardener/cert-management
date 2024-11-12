// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package istio

import (
	"strings"

	"github.com/gardener/controller-manager-library/pkg/resources"

	"github.com/gardener/cert-management/pkg/cert/source"
	ctrl "github.com/gardener/cert-management/pkg/controller"
	"github.com/gardener/cert-management/pkg/controller/source/ingress"
	"github.com/gardener/cert-management/pkg/controller/source/service"
)

var (
	// GroupKindGateway is the GroupKind for the Gateway resource.
	GroupKindGateway = resources.NewGroupKind("networking.istio.io", "Gateway")
	// GroupKindVirtualService is the GroupKind for the VirtualService resource.
	GroupKindVirtualService = resources.NewGroupKind("networking.istio.io", "VirtualService")
)

func init() {
	source.CertSourceController(source.NewCertSourceTypeForCreator("istio-gateways-dns", GroupKindGateway, newGatewaySource), nil).
		FinalizerDomain("cert.gardener.cloud").
		RequireLease(ctrl.SourceCluster).
		DeactivateOnCreationErrorCheck(deactivateOnMissingMainResource).
		Reconciler(newTargetSourcesReconciler, "targetsources").
		Reconciler(newVirtualServicesReconciler, "virtualservices").
		WorkerPool("targetsources", 2, 0).
		ReconcilerWatchesByGK("targetsources", service.MainResource, ingress.MainResource).
		WorkerPool("virtualservices", 2, 0).
		ReconcilerWatchesByGK("virtualservices", GroupKindVirtualService).
		MustRegister(ctrl.ControllerGroupSource)
}

func deactivateOnMissingMainResource(err error) bool {
	return strings.Contains(err.Error(), "gardener/cml/resources/UNKNOWN_RESOURCE") &&
		(strings.Contains(err.Error(), GroupKindGateway.String()) || strings.Contains(err.Error(), GroupKindVirtualService.String()))
}

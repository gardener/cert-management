// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package gatewayapi

import (
	"strings"

	ctrl "github.com/gardener/cert-management/pkg/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/cluster"
	"github.com/gardener/controller-manager-library/pkg/resources"

	"github.com/gardener/cert-management/pkg/cert/source"
)

const Group = "gateway.networking.k8s.io"

var (
	GroupKindGateway   = resources.NewGroupKind(Group, "Gateway")
	GroupKindHTTPRoute = resources.NewGroupKind(Group, "HTTPRoute")
)

func init() {
	source.CertSourceController(source.NewCertSourceTypeForCreator("k8s-gateways-dns", GroupKindGateway, NewGatewaySource), nil).
		FinalizerDomain("dns.gardener.cloud").
		DeactivateOnCreationErrorCheck(deactivateOnMissingMainResource).
		Reconciler(HTTPRoutesReconciler, "httproutes").
		Cluster(cluster.DEFAULT).
		WorkerPool("httproutes", 2, 0).
		ReconcilerWatchesByGK("httproutes", GroupKindHTTPRoute).
		MustRegister(ctrl.ControllerGroupSource)
}

func deactivateOnMissingMainResource(err error) bool {
	return strings.Contains(err.Error(), "gardener/cml/resources/UNKNOWN_RESOURCE") &&
		(strings.Contains(err.Error(), GroupKindGateway.String()) || strings.Contains(err.Error(), GroupKindHTTPRoute.String()))
}

/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package service

import (
	"github.com/gardener/controller-manager-library/pkg/resources"

	"github.com/gardener/cert-management/pkg/cert/source"
	ctrl "github.com/gardener/cert-management/pkg/controller"
)

// MainResource is the service resource.
var MainResource = resources.NewGroupKind("core", "Service")

func init() {
	source.CertSourceController(source.NewCertSourceTypeForExtractor("service-cert", MainResource, GetSecretName), nil).
		FinalizerDomain("cert.gardener.cloud").
		RequireLease(ctrl.SourceCluster).
		MustRegister(ctrl.ControllerGroupSource)
}

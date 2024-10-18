/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package add

import (
	"context"
	"fmt"

	"github.com/gardener/cert-management/pkg/certman2/apis/config"
	"github.com/gardener/cert-management/pkg/certman2/controller/source"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/cert-management/pkg/certman2/controller/source/gateways_crd_watchdog"
	"github.com/gardener/cert-management/pkg/certman2/controller/source/ingress"
	"github.com/gardener/cert-management/pkg/certman2/controller/source/istio_gateway"
	"github.com/gardener/cert-management/pkg/certman2/controller/source/k8s_gateway"
	"github.com/gardener/cert-management/pkg/certman2/controller/source/service"
)

// AddToManager adds all source controllers to the manager.
func AddToManager(mgr manager.Manager, cfg *config.CertManagerConfiguration, prestartClient client.Client) error {
	crdState, err := gateways_crd_watchdog.CheckGatewayCRDs(context.Background(), prestartClient)
	if err != nil {
		return fmt.Errorf("failed to check for relevant gateways CRDs: %w", err)
	}

	if err := (&gateways_crd_watchdog.Reconciler{
		CheckGatewayCRDsState: *crdState,
	}).AddToManager(mgr); err != nil {
		return fmt.Errorf("failed adding gateway CRD watchdog controller: %w", err)
	}

	if err := (&service.Reconciler{
		ReconcilerBase: source.ReconcilerBase{
			Class: cfg.Class,
		},
	}).AddToManager(mgr); err != nil {
		return fmt.Errorf("failed adding source Service controller: %w", err)
	}

	if err := (&ingress.Reconciler{
		ReconcilerBase: source.ReconcilerBase{
			Class: cfg.Class,
		},
	}).AddToManager(mgr); err != nil {
		return fmt.Errorf("failed adding source Ingress controller: %w", err)
	}

	if version, err := crdState.IstioGatewayVersion(); err != nil {
		mgr.GetLogger().Info("source istio-gateway controller disabled", "reason", err)
	} else if version == istio_gateway.VersionNone {
		mgr.GetLogger().Info("source istio-gateway controller disabled")
	} else {
		if err := (&istio_gateway.Reconciler{
			ReconcilerBase: source.ReconcilerBase{
				Class: cfg.Class,
			},
			ActiveVersion: version,
		}).AddToManager(mgr); err != nil {
			return fmt.Errorf("failed adding source istio-gateway controller: %w", err)
		}
	}

	if version, err := crdState.KubernetesGatewayVersion(); err != nil {
		mgr.GetLogger().Info("source k8s-gateway controller disabled", "reason", err)
	} else if version == k8s_gateway.VersionNone {
		mgr.GetLogger().Info("source k8s-gateway controller disabled")
	} else {
		if err := (&k8s_gateway.Reconciler{
			ReconcilerBase: source.ReconcilerBase{
				Class: cfg.Class,
			},
			ActiveVersion: version,
		}).AddToManager(mgr); err != nil {
			return fmt.Errorf("failed adding source k8s-gateway controller: %w", err)
		}
	}

	return nil
}

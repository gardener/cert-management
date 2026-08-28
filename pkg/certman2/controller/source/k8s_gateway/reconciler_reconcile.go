// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package k8s_gateway

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayapisv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapisv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/gardener/cert-management/pkg/certman2/controller/source/common"
	"github.com/gardener/cert-management/pkg/shared"
)

func (r *Reconciler) reconcile(
	ctx context.Context,
	log logr.Logger,
	gateway client.Object,
) (
	reconcile.Result,
	error,
) {
	log.Info("reconcile")

	var certInputMap common.CertInputMap
	if isRelevant(gateway, r.Class) {
		var err error
		certInputMap, err = r.getCertificateInputMap(ctx, log, gateway)
		if err != nil {
			r.Recorder.Eventf(gateway, corev1.EventTypeWarning, "Invalid", "%s", err)
			return reconcile.Result{}, err
		}
	}

	return r.DoReconcile(ctx, log, gateway, certInputMap)
}

func (r *Reconciler) getCertificateInputMap(ctx context.Context, log logr.Logger, gateway client.Object) (common.CertInputMap, error) {
	return common.GetCertInputByCollector(ctx, log, gateway, func(ctx context.Context, obj client.Object) ([]*common.TLSData, error) {
		var array []*common.TLSData

		var spec *gatewayapisv1.GatewaySpec
		switch data := obj.(type) {
		case *gatewayapisv1.Gateway:
			spec = &data.Spec
		case *gatewayapisv1beta1.Gateway:
			spec = &data.Spec
		default:
			return nil, fmt.Errorf("unexpected istio gateway type: %t", obj)
		}

		if spec != nil {
			for i, listener := range spec.Listeners {
				if listener.Protocol == gatewayapisv1.HTTPSProtocolType || listener.Protocol == gatewayapisv1.TLSProtocolType {
					if listener.TLS != nil && (listener.TLS.Mode == nil || *listener.TLS.Mode == gatewayapisv1.TLSModeTerminate) {
						if len(listener.TLS.CertificateRefs) != 1 {
							log.Info(fmt.Sprintf("warn: unexpected number %d of listeners[%d].tls.certificateRefs: cannot select secret for storing certificate",
								len(listener.TLS.CertificateRefs), i))
							continue
						}
						ref := listener.TLS.CertificateRefs[0]
						if ptr.Deref(ref.Group, "") != "" || ptr.Deref(ref.Kind, "Secret") != "Secret" {
							log.Info(fmt.Sprintf("warn: unexpected group/kind of listeners[%d].tls.certificateRefs: cannot select secret for storing certificate", i))
							continue
						}
						if len(ref.Name) == 0 {
							continue
						}
						tlsData := &common.TLSData{
							SecretName:  string(ref.Name),
							SectionName: string(listener.Name),
						}
						if ref.Namespace != nil {
							tlsData.SecretNamespace = string(*ref.Namespace)
						} else {
							tlsData.SecretNamespace = gateway.GetNamespace()
						}
						if listener.Hostname != nil {
							tlsData.Hosts = []string{string(*listener.Hostname)}
						}
						array = append(array, tlsData)
					}
				}
			}
		}

		if len(array) > 0 {
			gatewayKey := client.ObjectKeyFromObject(gateway)
			routes, err := r.listHTTPRoutes(ctx, new(gatewayKey), r.ActiveVersion)
			if err != nil {
				return nil, err
			}
			for _, item := range array {
				var listenerHost string
				if len(item.Hosts) > 0 {
					listenerHost = item.Hosts[0]
				}
				gl := gatewayListener{gateway: gatewayKey, listenerSectionName: item.SectionName}
				item.Hosts = r.appendHostsFromHTTPRoutes(gl, routes, item.Hosts, listenerHost)
			}
		}

		return array, nil
	})
}

func (r *Reconciler) appendHostsFromHTTPRoutes(gl gatewayListener, routes []client.Object, hosts []string, listenerHost string) []string {
	addHost := func(hosts []string, host string) []string {
		for _, h := range hosts {
			if h == host || shared.MatchesWildcardSingleSubdomain(host, h) {
				return hosts
			}
		}
		if listenerHost != "" {
			if !shared.MatchesWildcardAnySubdomain(host, listenerHost) && !shared.MatchesWildcardAnySubdomain(listenerHost, host) {
				// foreign host for another listener, do not add
				return hosts
			}
		}
		return append(hosts, host)
	}

	for _, route := range routes {
		switch r := route.(type) {
		case *gatewayapisv1.HTTPRoute:
			if matchesGatewayListener(r.Spec.ParentRefs, gl) {
				for _, h := range r.Spec.Hostnames {
					hosts = addHost(hosts, string(h))
				}
			}
		case *gatewayapisv1beta1.HTTPRoute:
			if matchesGatewayListener(r.Spec.ParentRefs, gl) {
				for _, h := range r.Spec.Hostnames {
					hosts = addHost(hosts, string(h))
				}
			}
		}
	}
	return hosts
}

// gatewayListener identifies a specific listener section within a Gateway resource.
type gatewayListener struct {
	gateway client.ObjectKey
	// listenerSectionName is an optional field to specify a listener of the gateway.
	listenerSectionName string
}

func matchesGatewayListener(parentRefs []gatewayapisv1.ParentReference, gl gatewayListener) bool {
	for _, ref := range parentRefs {
		if string(ref.Name) == gl.gateway.Name &&
			(ref.Namespace == nil || string(*ref.Namespace) == gl.gateway.Namespace) &&
			(ref.SectionName == nil || gl.listenerSectionName == "" || string(*ref.SectionName) == gl.listenerSectionName) {
			return true
		}
	}
	return false
}

func (r *Reconciler) listHTTPRoutes(ctx context.Context, gatewayKey *client.ObjectKey, version Version) ([]client.Object, error) {
	list := newHTTPRouteList(version)
	if err := r.Client.List(ctx, list); err != nil {
		return nil, err
	}
	var array []client.Object
	if err := meta.EachListItem(list, func(object runtime.Object) error {
		obj := object.(client.Object)
		gateways := extractGatewayNames(obj)
		for g := range gateways {
			if gatewayKey == nil || g == *gatewayKey {
				array = append(array, obj)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return array, nil
}

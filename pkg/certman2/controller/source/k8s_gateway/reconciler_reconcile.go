package k8s_gateway

import (
	"context"
	"fmt"
	"strings"

	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayapisv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapisv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayapisv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/gardener/cert-management/pkg/certman2/controller/source"
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

	var certInputMap source.CertInputMap
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

func (r *Reconciler) getCertificateInputMap(ctx context.Context, log logr.Logger, gateway client.Object) (source.CertInputMap, error) {
	return source.GetCertInputByCollector(ctx, log, gateway, func(ctx context.Context, obj client.Object) ([]*source.TLSData, error) {
		var array []*source.TLSData

		var spec *gatewayapisv1.GatewaySpec
		switch data := obj.(type) {
		case *gatewayapisv1.Gateway:
			spec = &data.Spec
		case *gatewayapisv1beta1.Gateway:
			spec = &data.Spec
		case *gatewayapisv1alpha2.Gateway:
			spec = &data.Spec
		default:
			return nil, fmt.Errorf("unexpected istio gateway type: %t", obj)
		}

		if spec != nil {
			for i, listener := range spec.Listeners {
				if listener.Protocol == gatewayapisv1.HTTPSProtocolType || listener.Protocol == gatewayapisv1.TLSProtocolType {
					if listener.TLS != nil && (listener.TLS.Mode == nil || *listener.TLS.Mode == gatewayapisv1.TLSModeTerminate) {
						if len(listener.TLS.CertificateRefs) != 1 {
							logger.Warnf("unexpected number %d of listeners[%d].tls.certificateRefs: cannot select secret for storing certificate",
								len(listener.TLS.CertificateRefs), i)
							continue
						}
						ref := listener.TLS.CertificateRefs[0]
						if !(ref.Group == nil || *ref.Group == "") && (ref.Kind == nil || *ref.Kind == "Secret") {
							logger.Warnf("unexpected group/kind of listeners[%d].tls.certificateRefs: cannot select secret for storing certificate", i)
							continue
						}
						if len(ref.Name) == 0 {
							continue
						}
						tlsData := &source.TLSData{SecretName: string(ref.Name)}
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
			routes, err := r.listHTTPRoutes(ctx, ptr.To(client.ObjectKeyFromObject(gateway)), r.ActiveVersion)
			if err != nil {
				return nil, err
			}
			for _, item := range array {
				item.Hosts = r.appendHostsFromHTTPRoutes(routes, item.Hosts)
			}
		}

		return array, nil
	})
}

func (r *Reconciler) appendHostsFromHTTPRoutes(routes []client.Object, hosts []string) []string {
	addHost := func(hosts []string, host string) []string {
		for _, h := range hosts {
			if h == host {
				return hosts
			}
			if strings.HasPrefix(h, "*.") && strings.HasSuffix(host, h[1:]) && !strings.Contains(host[:len(host)-len(h)+1], ".") {
				return hosts
			}
		}
		return append(hosts, host)
	}

	for _, route := range routes {
		switch r := route.(type) {
		case *gatewayapisv1.HTTPRoute:
			for _, h := range r.Spec.Hostnames {
				hosts = addHost(hosts, string(h))
			}
		case *gatewayapisv1beta1.HTTPRoute:
			for _, h := range r.Spec.Hostnames {
				hosts = addHost(hosts, string(h))
			}
		case *gatewayapisv1alpha2.HTTPRoute:
			for _, h := range r.Spec.Hostnames {
				hosts = addHost(hosts, string(h))
			}
		}
	}
	return hosts
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

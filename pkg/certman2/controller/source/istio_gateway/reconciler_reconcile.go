package istio_gateway

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	istionetworkingv1 "istio.io/client-go/pkg/apis/networking/v1"
	istionetworkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	istionetworkingv1beta1 "istio.io/client-go/pkg/apis/networking/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

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

		switch data := obj.(type) {
		case *istionetworkingv1.Gateway:
			for _, server := range data.Spec.Servers {
				if server.Tls != nil && server.Tls.CredentialName != "" {
					array = append(array, &source.TLSData{
						SecretNamespace: gateway.GetNamespace(),
						SecretName:      server.Tls.CredentialName,
						Hosts:           parsedHosts(server.Hosts),
					})
				}
			}
		case *istionetworkingv1beta1.Gateway:
			for _, server := range data.Spec.Servers {
				if server.Tls != nil && server.Tls.CredentialName != "" {
					array = append(array, &source.TLSData{
						SecretNamespace: gateway.GetNamespace(),
						SecretName:      server.Tls.CredentialName,
						Hosts:           parsedHosts(server.Hosts),
					})
				}
			}
		case *istionetworkingv1alpha3.Gateway:
			for _, server := range data.Spec.Servers {
				if server.Tls != nil && server.Tls.CredentialName != "" {
					array = append(array, &source.TLSData{
						SecretNamespace: gateway.GetNamespace(),
						SecretName:      server.Tls.CredentialName,
						Hosts:           parsedHosts(server.Hosts),
					})
				}
			}
		default:
			return nil, fmt.Errorf("unexpected istio gateway type: %t", obj)
		}
		if len(array) > 0 {
			gatewayKey := client.ObjectKeyFromObject(obj)
			virtualServices, err := r.listVirtualServices(ctx, &gatewayKey, r.ActiveVersion)
			if err != nil {
				return nil, err
			}
			for _, item := range array {
				item.Hosts = r.appendHostsFromVirtualServices(virtualServices, item.Hosts)
			}
		}
		return array, nil
	})
}

func (r *Reconciler) appendHostsFromVirtualServices(virtualServices []client.Object, hosts []string) []string {
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

	for _, vsvc := range virtualServices {
		switch r := vsvc.(type) {
		case *istionetworkingv1.VirtualService:
			for _, h := range r.Spec.Hosts {
				hosts = addHost(hosts, h)
			}
		case *istionetworkingv1beta1.VirtualService:
			for _, h := range r.Spec.Hosts {
				hosts = addHost(hosts, h)
			}
		case *istionetworkingv1alpha3.VirtualService:
			for _, h := range r.Spec.Hosts {
				hosts = addHost(hosts, h)
			}
		}
	}
	return hosts
}

func (r *Reconciler) listVirtualServices(ctx context.Context, gatewayKey *client.ObjectKey, version Version) ([]client.Object, error) {
	list := newVirtualServiceList(version)
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

func parsedHosts(serverHosts []string) []string {
	var hosts []string
	for _, serverHost := range serverHosts {
		if serverHost == "*" {
			continue
		}
		parts := strings.Split(serverHost, "/")
		if len(parts) == 2 {
			// first part is namespace
			hosts = append(hosts, parts[1])
		} else if len(parts) == 1 {
			hosts = append(hosts, parts[0])
		}
	}
	return hosts
}

// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package gatewayapi

import (
	"fmt"
	"strings"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gatewayapisv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapisv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/gardener/cert-management/pkg/cert/source"
	ctrlsource "github.com/gardener/cert-management/pkg/controller/source"
)

type httpRouteLister interface {
	ListHTTPRoutes(gateway *resources.ObjectName) ([]resources.ObjectData, error)
}

type gatewaySource struct {
	source.DefaultCertSource
	lister httpRouteLister
	state  *routesState
}

// NewGatewaySource is the DNSSource for gateways.gateway.networking.k8s.io resources.
func NewGatewaySource(c controller.Interface) (source.CertSource, error) {
	lister, err := newServiceLister(c)
	if err != nil {
		return nil, err
	}
	state, err := getOrCreateSharedState(c)
	if err != nil {
		return nil, err
	}
	return newGatewaySourceWithRouteLister(lister, state)
}

func newGatewaySourceWithRouteLister(lister httpRouteLister, state *routesState) (source.CertSource, error) {
	return &gatewaySource{lister: lister, DefaultCertSource: source.NewDefaultCertSource(nil), state: state}, nil
}

func (s *gatewaySource) Setup() error {
	routes, err := s.lister.ListHTTPRoutes(nil)
	if err != nil {
		return err
	}
	for _, route := range routes {
		gateways := extractGatewayNames(route)
		s.state.AddRoute(resources.NewObjectNameForData(route), gateways)
	}
	return nil
}

func (s *gatewaySource) GetCertsInfo(logger logger.LogContext, objData resources.ObjectData) (*source.CertsInfo, error) {
	return ctrlsource.GetCertsInfoByCollector(logger, objData, func(objData resources.ObjectData) ([]*ctrlsource.TLSData, error) {
		var array []*ctrlsource.TLSData

		var spec *gatewayapisv1.GatewaySpec
		switch data := objData.(type) {
		case *gatewayapisv1.Gateway:
			spec = &data.Spec
		case *gatewayapisv1beta1.Gateway:
			spec = &data.Spec
		default:
			return nil, fmt.Errorf("unexpected istio gateway type: %#v", objData)
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
						if ptr.Deref(ref.Group, "") != "" || ptr.Deref(ref.Kind, "Secret") != "Secret" {
							logger.Warnf("unexpected group/kind of listeners[%d].tls.certificateRefs: cannot select secret for storing certificate", i)
							continue
						}
						if len(ref.Name) == 0 {
							continue
						}
						tlsData := &ctrlsource.TLSData{SecretName: string(ref.Name)}
						if ref.Namespace != nil {
							ns := string(*ref.Namespace)
							tlsData.SecretNamespace = &ns
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
			routes, err := s.lister.ListHTTPRoutes(ptr.To(resources.NewObjectNameForData(objData)))
			if err != nil {
				return nil, err
			}
			for _, item := range array {
				item.Hosts = s.appendHostsFromHTTPRoutes(routes, item.Hosts)
			}
		}

		return array, nil
	})
}

func (s *gatewaySource) appendHostsFromHTTPRoutes(routes []resources.ObjectData, hosts []string) []string {
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
		}
	}
	return hosts
}

var _ httpRouteLister = &httprouteLister{}

type httprouteLister struct {
	httprouteResources resources.Interface
}

func newServiceLister(c controller.Interface) (*httprouteLister, error) {
	httprouteResources, err := c.GetMainCluster().Resources().GetByGK(resources.NewGroupKind(Group, "HTTPRoute"))
	if err != nil {
		return nil, err
	}
	return &httprouteLister{httprouteResources: httprouteResources}, nil
}

func (l *httprouteLister) ListHTTPRoutes(gateway *resources.ObjectName) ([]resources.ObjectData, error) {
	objs, err := l.httprouteResources.List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var array []resources.ObjectData
	for _, obj := range objs {
		gateways := extractGatewayNames(obj.Data())
		for g := range gateways {
			if gateway == nil || g == *gateway {
				array = append(array, obj.Data())
			}
		}
	}
	return array, nil
}

// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package istio

import (
	"fmt"
	"strings"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	istionetworkingv1 "istio.io/client-go/pkg/apis/networking/v1"
	istionetworkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	istionetworkingv1beta1 "istio.io/client-go/pkg/apis/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/gardener/cert-management/pkg/cert/source"
	ctrlsource "github.com/gardener/cert-management/pkg/controller/source"
	"github.com/gardener/cert-management/pkg/controller/source/ingress"
	"github.com/gardener/cert-management/pkg/controller/source/service"
)

type resourceLister interface {
	ListServices(selectors map[string]string) ([]resources.ObjectData, error)
	GetIngress(name resources.ObjectName) (resources.ObjectData, error)
	ListVirtualServices(gateway *resources.ObjectName) ([]resources.ObjectData, error)
}

type gatewaySource struct {
	source.DefaultCertSource
	lister resourceLister
	state  *resourcesState
}

func newGatewaySource(c controller.Interface) (source.CertSource, error) {
	lister, err := newResourceLister(c)
	if err != nil {
		return nil, err
	}
	state, err := getOrCreateSharedState(c)
	if err != nil {
		return nil, err
	}
	return newGatewaySourceWithResourceLister(lister, state)
}

func newGatewaySourceWithResourceLister(lister resourceLister, state *resourcesState) (source.CertSource, error) {
	return &gatewaySource{lister: lister, state: state, DefaultCertSource: source.NewDefaultCertSource(nil)}, nil
}

func (s *gatewaySource) Setup() error {
	virtualServices, err := s.lister.ListVirtualServices(nil)
	if err != nil {
		return err
	}
	for _, virtualService := range virtualServices {
		gateways := extractGatewayNames(virtualService)
		s.state.AddVirtualService(resources.NewObjectNameForData(virtualService), gateways)
	}
	return nil
}

func (s *gatewaySource) Deleted(logger logger.LogContext, key resources.ClusterObjectKey) {
	s.DefaultCertSource.Deleted(logger, key)
}

func (s *gatewaySource) GetCertsInfo(logger logger.LogContext, objData resources.ObjectData) (*source.CertsInfo, error) {
	return ctrlsource.GetCertsInfoByCollector(logger, objData, func(objData resources.ObjectData) ([]*ctrlsource.TLSData, error) {
		var array []*ctrlsource.TLSData

		var secretNamespace *string
		if v := objData.GetAnnotations()[source.AnnotSecretNamespace]; v != "" {
			secretNamespace = &v
		}

		switch data := objData.(type) {
		case *istionetworkingv1.Gateway:
			for _, server := range data.Spec.Servers {
				if server.Tls != nil && server.Tls.CredentialName != "" {
					array = append(array, &ctrlsource.TLSData{
						SecretName:      server.Tls.CredentialName,
						SecretNamespace: secretNamespace,
						Hosts:           parsedHosts(server.Hosts),
					})
				}
			}
		case *istionetworkingv1beta1.Gateway:
			for _, server := range data.Spec.Servers {
				if server.Tls != nil && server.Tls.CredentialName != "" {
					array = append(array, &ctrlsource.TLSData{
						SecretName:      server.Tls.CredentialName,
						SecretNamespace: secretNamespace,
						Hosts:           parsedHosts(server.Hosts),
					})
				}
			}
		case *istionetworkingv1alpha3.Gateway:
			for _, server := range data.Spec.Servers {
				if server.Tls != nil && server.Tls.CredentialName != "" {
					array = append(array, &ctrlsource.TLSData{
						SecretName:      server.Tls.CredentialName,
						SecretNamespace: secretNamespace,
						Hosts:           parsedHosts(server.Hosts),
					})
				}
			}
		default:
			return nil, fmt.Errorf("unexpected istio gateway type: %#v", objData)
		}
		if len(array) > 0 {
			virtualServices, err := s.lister.ListVirtualServices(ptr.To(resources.NewObjectNameForData(objData)))
			if err != nil {
				return nil, err
			}
			for _, item := range array {
				item.Hosts = s.appendHostsFromVirtualServices(virtualServices, item.Hosts)
			}
		}
		return array, nil
	})
}

func (s *gatewaySource) appendHostsFromVirtualServices(virtualServices []resources.ObjectData, hosts []string) []string {
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

type stdResourceLister struct {
	servicesResources        resources.Interface
	ingressResources         resources.Interface
	virtualServicesResources resources.Interface
}

var _ resourceLister = &stdResourceLister{}

func newResourceLister(c controller.Interface) (*stdResourceLister, error) {
	svcResources, err := c.GetMainCluster().Resources().GetByGK(service.MainResource)
	if err != nil {
		return nil, err
	}
	ingressResources, err := c.GetMainCluster().Resources().GetByGK(ingress.MainResource)
	if err != nil {
		return nil, err
	}
	virtualServicesResources, err := c.GetMainCluster().Resources().GetByGK(GroupKindVirtualService)
	if err != nil {
		return nil, err
	}
	return &stdResourceLister{
		servicesResources:        svcResources,
		ingressResources:         ingressResources,
		virtualServicesResources: virtualServicesResources,
	}, nil
}

func (s *stdResourceLister) ListServices(selectors map[string]string) ([]resources.ObjectData, error) {
	ls, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchLabels: selectors})
	if err != nil {
		return nil, err
	}
	objs, err := s.servicesResources.ListCached(ls)
	if err != nil {
		return nil, err
	}
	var array []resources.ObjectData
	for _, obj := range objs {
		array = append(array, obj.Data())
	}
	return array, nil
}

func (s *stdResourceLister) GetIngress(name resources.ObjectName) (resources.ObjectData, error) {
	obj, err := s.ingressResources.Get(name)
	if err != nil {
		return nil, err
	}
	return obj.Data(), nil
}

func (s *stdResourceLister) ListVirtualServices(gateway *resources.ObjectName) ([]resources.ObjectData, error) {
	objs, err := s.virtualServicesResources.List(metav1.ListOptions{})
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

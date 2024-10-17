/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package ingress

import (
	"fmt"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	networkingv1 "k8s.io/api/networking/v1"
	networkingv1beta1 "k8s.io/api/networking/v1beta1"

	"github.com/gardener/cert-management/pkg/cert/source"
	ctrlsource "github.com/gardener/cert-management/pkg/controller/source"
)

// CIngressSource is the ingress CertSource
type CIngressSource struct {
	source.DefaultCertSource
}

// NewIngressSource creates a CertSource
func NewIngressSource(_ controller.Interface) (source.CertSource, error) {
	return &CIngressSource{DefaultCertSource: source.DefaultCertSource{Events: map[resources.ClusterObjectKey]map[string]string{}}}, nil
}

// GetCertsInfo returns CertsInfo for the given object
func (s *CIngressSource) GetCertsInfo(logger logger.LogContext, objData resources.ObjectData) (*source.CertsInfo, error) {
	return ctrlsource.GetCertsInfoByCollector(logger, objData, func(data resources.ObjectData) ([]*ctrlsource.TLSData, error) {
		var array []*ctrlsource.TLSData
		switch data := data.(type) {
		case *networkingv1beta1.Ingress:
			if data.Spec.TLS == nil {
				return nil, nil
			}
			for _, item := range data.Spec.TLS {
				array = append(array, &ctrlsource.TLSData{
					SecretName: item.SecretName,
					Hosts:      item.Hosts,
				})
			}
			return array, nil
		case *networkingv1.Ingress:
			if data.Spec.TLS == nil {
				return nil, nil
			}
			for _, item := range data.Spec.TLS {
				array = append(array, &ctrlsource.TLSData{
					SecretName: item.SecretName,
					Hosts:      item.Hosts,
				})
			}
			return array, nil
		default:
			return nil, fmt.Errorf("unexpected ingress type: %#v", data)
		}
	})
}

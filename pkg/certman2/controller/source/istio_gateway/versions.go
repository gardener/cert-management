/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package istio_gateway

import (
	istionetworkingv1 "istio.io/client-go/pkg/apis/networking/v1"
	istionetworkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	istionetworkingv1beta1 "istio.io/client-go/pkg/apis/networking/v1beta1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Version is the version of the istio gateway.
type Version string

const (
	VersionV1       Version = "v1"
	VersionV1beta1  Version = "v1beta1"
	VersionV1alpha3 Version = "v1alpha3"
	VersionNone     Version = "<not deployed>"
)

// GetPreferredVersion retrieves the preferred version from the custom resource definition.
func GetPreferredVersion(crd *apiextensionsv1.CustomResourceDefinition) Version {
	var preferredVersion Version = VersionNone

	for _, v := range crd.Spec.Versions {
		if !v.Served {
			continue
		}
		var igv Version
		switch v.Name {
		case "v1":
			igv = VersionV1
		case "v1beta1":
			igv = VersionV1beta1
		case "v1alpha3":
			igv = VersionV1alpha3
		default:
			continue
		}
		if preferredVersion == VersionNone || preferredVersion > igv {
			preferredVersion = igv
		}
	}
	return preferredVersion
}

func newGateway(version Version) client.Object {
	switch version {
	case VersionV1:
		return &istionetworkingv1.Gateway{}
	case VersionV1beta1:
		return &istionetworkingv1beta1.Gateway{}
	case VersionV1alpha3:
		return &istionetworkingv1alpha3.Gateway{}
	default:
		return nil
	}
}

func newVirtualService(version Version) client.Object {
	switch version {
	case VersionV1:
		return &istionetworkingv1.VirtualService{}
	case VersionV1beta1:
		return &istionetworkingv1beta1.VirtualService{}
	case VersionV1alpha3:
		return &istionetworkingv1alpha3.VirtualService{}
	default:
		return nil
	}
}

func newVirtualServiceList(version Version) client.ObjectList {
	switch version {
	case VersionV1:
		return &istionetworkingv1.VirtualServiceList{}
	case VersionV1beta1:
		return &istionetworkingv1beta1.VirtualServiceList{}
	case VersionV1alpha3:
		return &istionetworkingv1alpha3.VirtualServiceList{}
	default:
		return nil
	}
}

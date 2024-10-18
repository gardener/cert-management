/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package istio_gateway

import (
	"strings"

	istionetworkingv1 "istio.io/client-go/pkg/apis/networking/v1"
	istionetworkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	istionetworkingv1beta1 "istio.io/client-go/pkg/apis/networking/v1beta1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Version is the version of the istio gateway.
type Version string

const (
	// VersionV1 is the v1 version of the istio gateway.
	VersionV1 Version = "v1"
	// VersionV1beta1 is the v1beta1 version of the istio gateway.
	VersionV1beta1 Version = "v1beta1"
	// VersionV1alpha3 is the v1alpha3 version of the istio gateway.
	VersionV1alpha3 Version = "v1alpha3"
	// VersionNone is zero version of the istio gateway.
	VersionNone Version = ""
)

// GetPreferredVersion retrieves the preferred version from the custom resource definition.
func GetPreferredVersion(crd *apiextensionsv1.CustomResourceDefinition) Version {
	if !strings.HasSuffix(crd.GetName(), ".networking.istio.io") {
		return VersionNone
	}

	versions := sets.Set[string]{}
	for _, v := range crd.Spec.Versions {
		if !v.Served {
			continue
		}
		versions.Insert(v.Name)
	}
	for _, vv := range []Version{VersionV1, VersionV1beta1, VersionV1alpha3} {
		if versions.Has(string(vv)) {
			return vv
		}
	}
	return VersionNone
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

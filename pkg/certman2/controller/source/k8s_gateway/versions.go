/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package k8s_gateway

import (
	"strings"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayapisv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapisv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayapisv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// Version is the version of the istio gateway.
type Version string

const (
	// VersionV1 is the v1 version of the Kubernetes Gateway API gateway.
	VersionV1 Version = "v1"
	// VersionV1beta1 is the v1beta1 version of the Kubernetes Gateway API gateway.
	VersionV1beta1 Version = "v1beta1"
	// VersionV1alpha2 is the v1alpha2 version of the Kubernetes Gateway API gateway.
	VersionV1alpha2 Version = "v1alpha2"
	// VersionNone is zero version of the Kubernetes Gateway API gateway.
	VersionNone Version = ""
)

// GetPreferredVersion retrieves the preferred version from the custom resource definition.
func GetPreferredVersion(crd *apiextensionsv1.CustomResourceDefinition) Version {
	if !strings.HasSuffix(crd.GetName(), "gateway.networking.k8s.io") {
		return VersionNone
	}

	versions := sets.Set[string]{}
	for _, v := range crd.Spec.Versions {
		if !v.Served {
			continue
		}
		versions.Insert(v.Name)
	}
	for _, vv := range []Version{VersionV1, VersionV1beta1, VersionV1alpha2} {
		if versions.Has(string(vv)) {
			return vv
		}
	}
	return VersionNone
}

func newGateway(version Version) client.Object {
	switch version {
	case VersionV1:
		return &gatewayapisv1.Gateway{}
	case VersionV1beta1:
		return &gatewayapisv1beta1.Gateway{}
	case VersionV1alpha2:
		return &gatewayapisv1alpha2.Gateway{}
	default:
		return nil
	}
}

func newHTTPRoute(version Version) client.Object {
	switch version {
	case VersionV1:
		return &gatewayapisv1.HTTPRoute{}
	case VersionV1beta1:
		return &gatewayapisv1beta1.HTTPRoute{}
	case VersionV1alpha2:
		return &gatewayapisv1alpha2.HTTPRoute{}
	default:
		return nil
	}
}

func newHTTPRouteList(version Version) client.ObjectList {
	switch version {
	case VersionV1:
		return &gatewayapisv1.HTTPRouteList{}
	case VersionV1beta1:
		return &gatewayapisv1beta1.HTTPRouteList{}
	case VersionV1alpha2:
		return &gatewayapisv1alpha2.HTTPRouteList{}
	default:
		return nil
	}
}

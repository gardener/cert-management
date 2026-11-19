// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package gatewayapi

import (
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/resources"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	gatewayapisv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapisv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// namespaceLister fetches the labels of a namespace, needed for the
// allowedRoutes "Selector" case.
type namespaceLister interface {
	NamespaceLabels(name string) (labels.Set, error)
}

var _ namespaceLister = &cachedNamespaceLister{}

type cachedNamespaceLister struct {
	namespaces resources.Interface
}

func newNamespaceLister(c controller.Interface) (*cachedNamespaceLister, error) {
	nsResources, err := c.GetMainCluster().Resources().GetByExample(&corev1.Namespace{})
	if err != nil {
		return nil, err
	}
	return &cachedNamespaceLister{namespaces: nsResources}, nil
}

func (l *cachedNamespaceLister) NamespaceLabels(name string) (labels.Set, error) {
	obj, err := l.namespaces.GetCached(name)
	if err != nil {
		return nil, err
	}
	return obj.GetLabels(), nil
}

// listenerAdmitsNamespace reports whether a single listener permits routes from
// routeNamespace to attach, per Gateway API allowedRoutes semantics. The default
// (unset allowedRoutes) is "Same", i.e. only the gateway's own namespace.
func listenerAdmitsNamespace(nsLister namespaceLister, gatewayNamespace, routeNamespace string, ar *gatewayapisv1.AllowedRoutes) (bool, error) {
	// shortcut: a Selector may exclude the gateway's own namespace, but we still admit
	// same-namespace routes; upgrade to honor an own-namespace-excluding Selector if needed.
	if routeNamespace == gatewayNamespace {
		return true, nil
	}
	from := gatewayapisv1.NamespacesFromSame
	if ar != nil && ar.Namespaces != nil && ar.Namespaces.From != nil {
		from = *ar.Namespaces.From
	}
	switch from {
	case gatewayapisv1.NamespacesFromAll:
		return true, nil
	case gatewayapisv1.NamespacesFromSelector:
		if ar.Namespaces.Selector == nil {
			return false, nil
		}
		selector, err := metav1.LabelSelectorAsSelector(ar.Namespaces.Selector)
		if err != nil {
			return false, err
		}
		nsLabels, err := nsLister.NamespaceLabels(routeNamespace)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return false, nil // deleted namespace matches no selector; let cleanup proceed
			}
			return false, err
		}
		return selector.Matches(nsLabels), nil
	}
	return false, nil
}

// listenerAllowedRoutes maps each listener's section name to its allowedRoutes,
// normalizing both API versions to the v1 type. Admission must be evaluated per
// listener, since a route's hostnames are attached to the specific listener it
// targets, not to the gateway as a whole.
func listenerAllowedRoutes(obj resources.ObjectData) map[string]*gatewayapisv1.AllowedRoutes {
	result := map[string]*gatewayapisv1.AllowedRoutes{}
	switch data := obj.(type) {
	case *gatewayapisv1.Gateway:
		for _, l := range data.Spec.Listeners {
			result[string(l.Name)] = l.AllowedRoutes
		}
	case *gatewayapisv1beta1.Gateway:
		for _, l := range data.Spec.Listeners {
			result[string(l.Name)] = l.AllowedRoutes // v1beta1.AllowedRoutes is an alias for v1.AllowedRoutes
		}
	}
	return result
}

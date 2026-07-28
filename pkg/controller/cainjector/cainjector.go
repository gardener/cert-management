/*
 * SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package cainjector contains opt-in controllers that populate the caBundle fields of injectable
// Kubernetes resources (ValidatingWebhookConfiguration, MutatingWebhookConfiguration,
// CustomResourceDefinition conversion webhooks and APIServices) from a CA source driven by
// annotations. It is the controller-manager-library (CML) based port of the certman2 CA injector.
package cainjector

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	ctrl "github.com/gardener/cert-management/pkg/controller"
)

const (
	// AnnotationInjectCAFrom is set on an injectable resource to inject the CA bundle taken from the
	// secret of the referenced certificate. Value format: "<namespace>/<certificate-name>".
	AnnotationInjectCAFrom = "cert.gardener.cloud/inject-ca-from"
	// AnnotationInjectCAFromSecret is set on an injectable resource to inject the CA bundle taken
	// directly from the referenced secret. Value format: "<namespace>/<secret-name>". The referenced
	// secret must carry the AnnotationAllowDirectInjection annotation set to "true".
	AnnotationInjectCAFromSecret = "cert.gardener.cloud/inject-ca-from-secret"
	// AnnotationAllowDirectInjection must be set to "true" on a secret to allow direct CA injection
	// via AnnotationInjectCAFromSecret.
	AnnotationAllowDirectInjection = "cert.gardener.cloud/allow-direct-injection"

	// caCrtKey is the key in the secret data holding the CA certificate.
	caCrtKey = "ca.crt"

	// requeueDelay is the delay after which an injectable resource is re-checked while its CA source
	// is not (yet) available.
	requeueDelay = 10 * time.Second
)

// objectGetter fetches a named object into the given target. It is satisfied by
// resources.Interface and allows the CA-resolution logic to be tested with a lightweight fake.
type objectGetter interface {
	GetInto(resources.ObjectName, resources.ObjectData) (resources.Object, error)
}

// injector holds the resource handles and the reverse index shared by all four CA injector
// reconcilers. Each per-kind reconciler embeds it. The reverse index maps a CA source (certificate
// or secret, keyed by "<namespace>/<name>") to the set of injectable resource keys that reference it,
// so that changes of a certificate or secret re-trigger the referencing injectable resources.
type injector struct {
	controller      controller.Interface
	certResources   objectGetter
	secretResources objectGetter

	lock       sync.Mutex
	certRefs   map[string]resources.ClusterObjectKeySet
	secretRefs map[string]resources.ClusterObjectKeySet
}

// newInjector creates an injector bound to the certificate and secret resources of the source cluster.
func newInjector(c controller.Interface) (*injector, error) {
	sourceCluster := c.GetCluster(ctrl.SourceCluster)
	certResources, err := sourceCluster.Resources().GetByExample(&api.Certificate{})
	if err != nil {
		return nil, fmt.Errorf("getting certificate resources failed: %w", err)
	}
	secretResources, err := sourceCluster.Resources().GetByExample(&corev1.Secret{})
	if err != nil {
		return nil, fmt.Errorf("getting secret resources failed: %w", err)
	}
	return &injector{
		controller:      c,
		certResources:   certResources,
		secretResources: secretResources,
		certRefs:        map[string]resources.ClusterObjectKeySet{},
		secretRefs:      map[string]resources.ClusterObjectKeySet{},
	}, nil
}

// resolveCA determines the CA bundle to inject from the given annotations. The returned requeue flag
// signals that the CA source is not yet available and the injectable resource should be rechecked
// later. A nil CA bundle without requeue means there is nothing to inject (no annotation or the guard
// for direct injection is not fulfilled).
func (i *injector) resolveCA(defaultNamespace string, annotations map[string]string) (ca []byte, requeue bool, err error) {
	if ref, ok := annotations[AnnotationInjectCAFrom]; ok {
		return i.resolveCAFromCertificate(defaultNamespace, ref)
	}
	if ref, ok := annotations[AnnotationInjectCAFromSecret]; ok {
		return i.resolveCAFromSecret(defaultNamespace, ref, true)
	}
	return nil, false, nil
}

func (i *injector) resolveCAFromCertificate(defaultNamespace, ref string) ([]byte, bool, error) {
	namespace, name, err := splitNamespacedName(defaultNamespace, ref)
	if err != nil {
		return nil, false, fmt.Errorf("invalid %s annotation %q: %w", AnnotationInjectCAFrom, ref, err)
	}

	cert := &api.Certificate{}
	if _, err := i.certResources.GetInto(resources.NewObjectName(namespace, name), cert); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("getting certificate %s/%s failed: %w", namespace, name, err)
	}

	secretNamespace := namespace
	secretName := ""
	switch {
	case cert.Spec.SecretName != nil && *cert.Spec.SecretName != "":
		secretName = *cert.Spec.SecretName
	case cert.Spec.SecretRef != nil && cert.Spec.SecretRef.Name != "":
		secretName = cert.Spec.SecretRef.Name
		if cert.Spec.SecretRef.Namespace != "" {
			secretNamespace = cert.Spec.SecretRef.Namespace
		}
	}
	if secretName == "" {
		return nil, true, nil
	}

	// The secret is referenced by the certificate itself, so the direct-injection guard is not required.
	return i.resolveCAFromSecret(secretNamespace, secretNamespace+"/"+secretName, false)
}

func (i *injector) resolveCAFromSecret(defaultNamespace, ref string, checkAllowAnnotation bool) ([]byte, bool, error) {
	namespace, name, err := splitNamespacedName(defaultNamespace, ref)
	if err != nil {
		return nil, false, fmt.Errorf("invalid secret reference %q: %w", ref, err)
	}

	secret := &corev1.Secret{}
	if _, err := i.secretResources.GetInto(resources.NewObjectName(namespace, name), secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("getting secret %s/%s failed: %w", namespace, name, err)
	}

	if checkAllowAnnotation && secret.Annotations[AnnotationAllowDirectInjection] != "true" {
		return nil, false, nil
	}

	ca := secret.Data[caCrtKey]
	if len(ca) == 0 {
		return nil, true, nil
	}
	return ca, false, nil
}

// trackRefs updates the reverse index for the given injectable resource key according to its
// annotations. The injectable key is removed from all previous entries first, so that stale
// references (e.g. after an annotation change) do not linger.
func (i *injector) trackRefs(key resources.ClusterObjectKey, defaultNamespace string, annotations map[string]string) {
	i.lock.Lock()
	defer i.lock.Unlock()

	removeFromIndex(i.certRefs, key)
	removeFromIndex(i.secretRefs, key)

	if ref, ok := annotations[AnnotationInjectCAFrom]; ok {
		if namespace, name, err := splitNamespacedName(defaultNamespace, ref); err == nil {
			addToIndex(i.certRefs, namespace+"/"+name, key)
		}
		return
	}
	if ref, ok := annotations[AnnotationInjectCAFromSecret]; ok {
		if namespace, name, err := splitNamespacedName(defaultNamespace, ref); err == nil {
			addToIndex(i.secretRefs, namespace+"/"+name, key)
		}
	}
}

// forgetRefs removes the given injectable resource key from the reverse index.
func (i *injector) forgetRefs(key resources.ClusterObjectKey) {
	i.lock.Lock()
	defer i.lock.Unlock()
	removeFromIndex(i.certRefs, key)
	removeFromIndex(i.secretRefs, key)
}

// enqueueReferers enqueues all injectable resources referencing the changed certificate or secret.
func (i *injector) enqueueReferers(logger logger.LogContext, sourceKey resources.ClusterObjectKey) reconcile.Status {
	for _, referer := range i.referers(sourceKey) {
		if err := i.controller.EnqueueKey(referer); err != nil {
			logger.Warnf("enqueue of %s failed: %s", referer, err)
		}
	}
	return reconcile.Succeeded(logger)
}

// referers returns the injectable resource keys referencing the given certificate or secret.
func (i *injector) referers(sourceKey resources.ClusterObjectKey) []resources.ClusterObjectKey {
	name := sourceKey.Namespace() + "/" + sourceKey.Name()

	i.lock.Lock()
	defer i.lock.Unlock()
	var index map[string]resources.ClusterObjectKeySet
	switch sourceKey.Kind() {
	case api.CertificateKind:
		index = i.certRefs
	case "Secret":
		index = i.secretRefs
	}
	var referers []resources.ClusterObjectKey
	for referer := range index[name] {
		referers = append(referers, referer)
	}
	return referers
}

// isCASource reports whether the given object is one of the watched CA sources (certificate or secret).
func isCASource(obj resources.Object) bool {
	return obj.IsA(&api.Certificate{}) || obj.IsA(&corev1.Secret{})
}

// isCASourceKind reports whether the given kind is one of the watched CA sources.
func isCASourceKind(kind string) bool {
	return kind == api.CertificateKind || kind == "Secret"
}

func addToIndex(index map[string]resources.ClusterObjectKeySet, name string, key resources.ClusterObjectKey) {
	set, ok := index[name]
	if !ok {
		set = resources.NewClusterObjectKeySet()
		index[name] = set
	}
	set.Add(key)
}

func removeFromIndex(index map[string]resources.ClusterObjectKeySet, key resources.ClusterObjectKey) {
	for name, set := range index {
		set.Remove(key)
		if len(set) == 0 {
			delete(index, name)
		}
	}
}

// splitNamespacedName splits a "<namespace>/<name>" reference. A bare "<name>" falls back to the given
// default namespace.
func splitNamespacedName(defaultNamespace, ref string) (namespace, name string, err error) {
	parts := strings.Split(ref, "/")
	switch len(parts) {
	case 1:
		if parts[0] == "" {
			return "", "", fmt.Errorf("empty reference")
		}
		return defaultNamespace, parts[0], nil
	case 2:
		if parts[0] == "" || parts[1] == "" {
			return "", "", fmt.Errorf("reference %q must be of form <namespace>/<name>", ref)
		}
		return parts[0], parts[1], nil
	default:
		return "", "", fmt.Errorf("reference %q must be of form <namespace>/<name>", ref)
	}
}

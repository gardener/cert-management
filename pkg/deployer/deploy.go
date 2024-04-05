/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package deployer

import (
	"context"
	"strings"
	"time"

	"github.com/gardener/cert-management/pkg/deployer/kustomize"
	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	"github.com/gardener/gardener/pkg/component"
	"github.com/gardener/gardener/pkg/utils/managedresources"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	runtimeserializer "k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	kubernetesscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	certv1alpha1 "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/deployer/kubernetes"
)

// ManagedResourceName is the name of the 'cert-management' managed resource.
const (
	ManagedResourceName = "cert-management-deployment"
	// TimeoutWaitForManagedResource is the timeout used while waiting for the ManagedResources to become healthy
	// or deleted.
	TimeoutWaitForManagedResource = 2 * time.Minute
)

func init() {
	schemeBuilder := runtime.NewSchemeBuilder(
		kubernetesscheme.AddToScheme,
		certv1alpha1.AddToScheme,
		resourcesv1alpha1.AddToScheme,
		apiextensionsv1.AddToScheme,
	)

	utilruntime.Must(schemeBuilder.AddToScheme(Scheme))
}

var (
	// Scheme is the scheme relevant for the deployer.
	Scheme = runtime.NewScheme()
	// CodecFactory is the codec factory for the scheme.
	CodecFactory = runtimeserializer.NewCodecFactory(Scheme)
	serializer   = json.NewSerializerWithOptions(json.DefaultMetaFactory, Scheme, Scheme, json.SerializerOptions{Yaml: true, Pretty: false, Strict: false})
)

type deployer struct {
	client client.Client
	values Values
	class  component.Class
}

var _ kustomize.DeployWaiterEx = (*deployer)(nil)

// New returns a new 'cert-management' deployer instance.
func New(
	client client.Client,
	values Values,
) kustomize.DeployWaiterEx {
	if values.ManagedResourceConfig.Namespace == "" {
		values.ManagedResourceConfig.Namespace = values.Namespace
	}

	return &deployer{
		client: client,
		values: values,
		class:  component.Application,
	}
}

func (d *deployer) Deploy(ctx context.Context) error {
	serviceAccount := kubernetes.EmptyServiceAccount(d.values.Name, d.values.Namespace)
	clusterRole := kubernetes.EmptyClusterRole(d.values.Name)
	clusterRoleBinding := kubernetes.EmptyClusterRoleBinding(d.values.Name)
	role := kubernetes.EmptyRole(d.values.Name, d.values.Namespace)
	roleBinding := kubernetes.EmptyRoleBinding(d.values.Name, d.values.Namespace)
	deployment := kubernetes.EmptyDeployment(d.values.Name, d.values.Namespace)

	codec := CodecFactory.CodecForVersions(serializer, serializer, apiextensionsv1.SchemeGroupVersion, apiextensionsv1.SchemeGroupVersion)
	crdCertificateRevocations, err := kubernetes.EmptyCRDRevocations(codec)
	if err != nil {
		return err
	}
	crdCertificates, err := kubernetes.EmptyCRDCertificates(codec)
	if err != nil {
		return err
	}
	crdIssuers, err := kubernetes.EmptyCRDIssuers(codec)
	if err != nil {
		return err
	}

	resourceConfigs := []component.ResourceConfig{
		{Obj: crdCertificateRevocations, Class: d.class},
		{Obj: crdCertificates, Class: d.class},
		{Obj: crdIssuers, Class: d.class},
		{Obj: serviceAccount, Class: d.class},
		{Obj: clusterRole, Class: d.class, MutateFn: func() {
			kubernetes.ReconcileClusterRole(clusterRole)
		}},
		{Obj: clusterRoleBinding, Class: d.class, MutateFn: func() {
			kubernetes.ReconcileClusterRoleBinding(clusterRoleBinding, clusterRole.Name, serviceAccount.Name, serviceAccount.Namespace)
		}},
		{Obj: role, Class: d.class, MutateFn: func() {
			kubernetes.ReconcileRole(role)
		}},
		{Obj: roleBinding, Class: d.class, MutateFn: func() {
			kubernetes.ReconcileRoleBinding(roleBinding, serviceAccount.Name, role.Name)
		}},
	}

	var caBundleSecret *corev1.Secret
	if bundleData := d.values.Config.CACertificateBundle; bundleData != nil {
		caBundleSecret = kubernetes.EmptyCABundleCertificateSecret(d.values.Name, d.values.Namespace)

		resourceConfigs = append(resourceConfigs, component.ResourceConfig{Obj: caBundleSecret, Class: d.class, MutateFn: func() {
			kubernetes.ReconcileCABundleCertificateSecret(caBundleSecret, []byte(*bundleData))
		}})
	}
	resourceConfigs = append(resourceConfigs, component.ResourceConfig{Obj: deployment, Class: d.class, MutateFn: func() {
		kubernetes.MutateDeployment(deployment, d.values.PodLabels, d.values.Name, d.values.Image, d.values.Config.HttpServerPort, caBundleSecret)
	}})

	registry := managedresources.NewRegistry(Scheme, CodecFactory, serializer)
	for _, r := range resourceConfigs {
		if r.MutateFn != nil {
			r.MutateFn()
		}
		if err := registry.Add(r.Obj); err != nil {
			return err
		}
	}
	return managedresources.Create(ctx, d.client, d.values.ManagedResourceConfig.Namespace, ManagedResourceName, d.values.ManagedResourceConfig.Labels,
		true, d.values.ManagedResourceConfig.Class, registry.SerializedObjects(), ptr.To(false), d.values.ManagedResourceConfig.InjectedLabels, nil)
}

func (d *deployer) Destroy(ctx context.Context) error {
	return managedresources.Delete(ctx, d.client, d.values.ManagedResourceConfig.Namespace, ManagedResourceName, true)
}

func (d *deployer) Wait(ctx context.Context) error {
	return managedresources.WaitUntilHealthy(ctx, d.client, d.values.Namespace, ManagedResourceName)
	timeoutCtx, cancel := context.WithTimeout(ctx, TimeoutWaitForManagedResource)
	defer cancel()

	return managedresources.WaitUntilHealthy(timeoutCtx, d.client, d.values.Namespace, ManagedResourceName)
}

func (d *deployer) WaitCleanup(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, TimeoutWaitForManagedResource)
	defer cancel()

	return managedresources.WaitUntilDeleted(timeoutCtx, d.client, d.values.Namespace, ManagedResourceName)
}

func (d *deployer) Images() map[string]string {
	images := map[string]string{}
	parts := strings.SplitN(d.values.Image, ":", 2)
	tag := "unknown"
	if len(parts) == 2 {
		tag = parts[1]
	}
	images[parts[0]] = tag
	return images
}

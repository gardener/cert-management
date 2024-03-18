/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package deployer

import (
	"context"

	"github.com/gardener/gardener/pkg/component"
	"github.com/gardener/gardener/pkg/utils/managedresources"
	"k8s.io/apimachinery/pkg/runtime"
	runtimeserializer "k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/cert-management/pkg/deployer/kubernetes"
)

var (
	scheme       = runtime.NewScheme()
	codecFactory = runtimeserializer.NewCodecFactory(scheme)
	serializer   = json.NewSerializerWithOptions(json.DefaultMetaFactory, scheme, scheme, json.SerializerOptions{Yaml: true, Pretty: false, Strict: false})
)

type deployer struct {
	client client.Client
	values Values
	class  component.Class
}

var _ component.DeployWaiter = (*deployer)(nil)

// New returns a new 'cert-management' deployer instance.
func New(client client.Client, values Values, class component.Class) component.DeployWaiter {
	return &deployer{
		client: client,
		values: values,
		class:  class,
	}
}

// ManagedResourceName is the name of the 'cert-management' managed resource.
const ManagedResourceName = "cert-management-deployment"

func (d *deployer) Deploy(ctx context.Context) error {
	serviceAccount := kubernetes.EmptyServiceAccount(d.values.Name, d.values.Namespace)
	clusterRole := kubernetes.EmptyClusterRole(d.values.Name)
	clusterRoleBinding := kubernetes.EmptyClusterRoleBinding(d.values.Name)
	role := kubernetes.EmptyRole(d.values.Name, d.values.Namespace)
	roleBinding := kubernetes.EmptyRoleBinding(d.values.Name, d.values.Namespace)
	deployment := kubernetes.EmptyDeployment(d.values.Name, d.values.Namespace)

	resourceConfigs := []component.ResourceConfig{
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
		{Obj: deployment, Class: d.class, MutateFn: func() {
			kubernetes.MutateDeployment(deployment, d.values.PodLabels, d.values.Name, d.values.Image, d.values.Config.HttpServerPort)
		}},
	}

	return component.DeployResourceConfigs(
		ctx,
		d.client,
		d.values.Namespace,
		// TODO(timuthy): Change utility in `gardener/gardener` to not pass shoot here.
		component.ClusterTypeShoot,
		ManagedResourceName,
		managedresources.NewRegistry(scheme, codecFactory, serializer),
		resourceConfigs,
	)
}

func (d *deployer) Destroy(ctx context.Context) error {
	//TODO implement me
	panic("implement me")
}

func (d *deployer) Wait(ctx context.Context) error {
	// Only wait properly if managed resource is used.
	if d.class == component.Runtime {
		return nil
	}

	return managedresources.WaitUntilHealthy(ctx, d.client, d.values.Namespace, ManagedResourceName)
}

func (d *deployer) WaitCleanup(ctx context.Context) error {
	//TODO implement me
	panic("implement me")
}

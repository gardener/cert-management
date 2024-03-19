/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package gen

import (
	"bytes"
	"context"
	"os"

	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	"github.com/gardener/gardener/pkg/component"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/cert-management/pkg/deployer"
)

// Generate renders manifests from 'cert-management' and write the results to the given output dir.
func Generate(ctx context.Context, valuesFilePath string, outputDir string) error {
	valuesBytes, err := os.ReadFile(valuesFilePath)
	if err != nil {
		return err
	}

	values := &deployer.Values{}
	if err := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(valuesBytes), 1024).Decode(values); err != nil {
		return err
	}

	deployerScheme := deployer.Scheme
	objectTracker := testing.NewObjectTracker(deployerScheme, scheme.Codecs.UniversalDecoder())
	cl := fakeclient.NewClientBuilder().WithScheme(deployerScheme).WithObjectTracker(objectTracker).Build()

	depl := deployer.New(cl, *values, component.Application)
	if err := depl.Deploy(ctx); err != nil {
		return err
	}

	managedResource := &resourcesv1alpha1.ManagedResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deployer.ManagedResourceName,
			Namespace: values.Namespace,
		},
	}

	if err := cl.Get(ctx, client.ObjectKeyFromObject(managedResource), managedResource); err != nil {
		return err
	}

	for _, secretRef := range managedResource.Spec.SecretRefs {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretRef.Name,
				Namespace: managedResource.Namespace,
			},
		}

		if err := cl.Get(ctx, client.ObjectKeyFromObject(secret), secret); err != nil {
			return err
		}

		for k, d := range secret.Data {
			if err := os.WriteFile(outputDir+"/"+k, d, os.FileMode(0600)); err != nil {
				return err
			}
		}
	}

	return nil
}

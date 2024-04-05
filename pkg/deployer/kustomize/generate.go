/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package kustomize

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"text/template"

	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	"github.com/gardener/gardener/pkg/component"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// DeployWaiterEx is an extended interface of DeployWaiter to access the images.
type DeployWaiterEx interface {
	component.DeployWaiter
	// Images returns image map with key containing image name and value the image tag.
	Images() map[string]string
}

// DeployWaiterExCreator is factory function to create a DeployWaiterEx.
type DeployWaiterExCreator func(cl client.Client) (DeployWaiterEx, error)

// GenerateValues are values for the Generate method.
type GenerateValues struct {
	Scheme              *runtime.Scheme
	CodecFactory        serializer.CodecFactory
	ManagedResourceName string
	Namespace           string
	OutputDir           string
}

// Generate generates manifests from deployer to values.OutputDir folder.
func Generate(ctx context.Context, creator DeployWaiterExCreator, values GenerateValues) error {
	objectTracker := testing.NewObjectTracker(values.Scheme, values.CodecFactory.UniversalDecoder())
	cl := fakeclient.NewClientBuilder().WithScheme(values.Scheme).WithObjectTracker(objectTracker).Build()

	depl, err := creator(cl)
	if err != nil {
		return err
	}
	if err := depl.Deploy(ctx); err != nil {
		return err
	}

	managedResource := &resourcesv1alpha1.ManagedResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      values.ManagedResourceName,
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

		if err := os.MkdirAll(values.OutputDir, os.FileMode(0755)); err != nil {
			return err
		}
		var resources []string
		for name, d := range secret.Data {
			resources = append(resources, name)
			if err := os.WriteFile(filepath.Join(values.OutputDir, name), d, os.FileMode(0644)); err != nil {
				return err
			}
		}
		sort.Strings(resources)

		if err := writeKustomizeFile(values.OutputDir, resources, depl.Images()); err != nil {
			return err
		}
		path, err := filepath.Abs(values.OutputDir)
		if err != nil {
			path = values.OutputDir
		}
		fmt.Printf("Written manifests to directory %s\n", path)
	}

	return nil
}

func writeKustomizeFile(outputDir string, resources []string, images map[string]string) error {
	tmpl, err := template.New("kustomization").Parse(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
{{- range .resources}}
  - {{.}}
{{- end}}
images:
{{- range $name, $tag := .images}}
  - name: {{ $name }}
    newName: {{ $name }}
    newTag: {{ $tag }}
{{- end}}
`)
	if err != nil {
		return err
	}

	buf := bytes.Buffer{}
	err = tmpl.Execute(&buf, map[string]any{"resources": resources, "images": images})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outputDir, "kustomization.yaml"), buf.Bytes(), os.FileMode(0644))
}

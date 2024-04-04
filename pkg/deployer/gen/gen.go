/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package gen

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"text/template"

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

// GenerateWithArgs renders kustomize base profile from 'cert-management' with given command line arguments.
func GenerateWithArgs(args []string, subcommand string) int {
	var (
		flagSet = flag.NewFlagSet(fmt.Sprintf("%s %s", os.Args[0], subcommand), flag.ExitOnError)
		values  = flagSet.String("values", "values.yaml", "path to file with values for chart generation")
		output  = flagSet.String("output", "bundle.yaml", "output directory for chart bundle manifest")
	)
	if err := flagSet.Parse(args); err != nil {
		println(err.Error())
		flagSet.Usage()
		return 1
	}

	if err := Generate(context.Background(), *values, *output); err != nil {
		println(err.Error())
		return 2
	}
	return 0
}

// Generate renders kustomize base profile from 'cert-management' and write the results to the given output dir.
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

	depl := deployer.New(cl, *values, component.Application, "default")
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

		os.MkdirAll(outputDir, os.FileMode(0755))
		var resources []string
		for name, d := range secret.Data {
			resources = append(resources, name)
			if err := os.WriteFile(filepath.Join(outputDir, name), d, os.FileMode(0644)); err != nil {
				return err
			}
		}
		sort.Strings(resources)

		if err := writeKustomizeFile(outputDir, resources, depl.Images()); err != nil {
			return err
		}
		path, err := filepath.Abs(outputDir)
		if err != nil {
			path = outputDir
		}
		fmt.Printf("Written base manifest to directory %s\n", path)
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

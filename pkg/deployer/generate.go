/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package deployer

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/gardener/cert-management/pkg/deployer/kustomize"
	"k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GenerateManifestsCommand renders kustomize base profile from 'cert-management' with given command line arguments.
func GenerateManifestsCommand(args []string, subcommand string) {
	var (
		flagSet = flag.NewFlagSet(fmt.Sprintf("%s %s", os.Args[0], subcommand), flag.ExitOnError)
		values  = flagSet.String("values", "values.yaml", "path to file with values for chart generation")
		output  = flagSet.String("output", "manifests/profiles/base", "output directory for chart bundle manifest")
	)
	if err := flagSet.Parse(args); err != nil {
		println(err.Error())
		flagSet.Usage()
		os.Exit(1)
	}

	if err := GenerateManifests(context.Background(), *values, *output); err != nil {
		println(err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

// GenerateManifests renders kustomize base profile for 'cert-management' and write the results to the given output dir.
func GenerateManifests(ctx context.Context, valuesFilePath string, outputDir string) error {
	valuesBytes, err := os.ReadFile(valuesFilePath)
	if err != nil {
		return err
	}

	values := &Values{}
	if err := yaml.Unmarshal(valuesBytes, values); err != nil {
		return err
	}

	creator := func(cl client.Client) (kustomize.DeployWaiterEx, error) {
		return New(cl, *values), nil
	}

	return kustomize.Generate(ctx, creator, kustomize.GenerateValues{
		Scheme:              Scheme,
		CodecFactory:        CodecFactory,
		ManagedResourceName: ManagedResourceName,
		Namespace:           values.Namespace,
		OutputDir:           outputDir,
	})
}

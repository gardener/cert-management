//go:build tools
// +build tools

// SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// This package imports things required by build scripts, to force `go mod` to see them as dependencies
package tools

import (
	_ "github.com/ahmetb/gen-crd-api-reference-docs"
	_ "github.com/onsi/ginkgo/v2/ginkgo"
	_ "github.com/onsi/gomega"
	_ "golang.org/x/lint/golint"
	_ "k8s.io/code-generator"
	_ "k8s.io/kube-openapi/cmd/openapi-gen"
	_ "sigs.k8s.io/kind"

	_ "github.com/gardener/controller-manager-library/hack"

	_ "golang.org/x/tools/cmd/goimports" // import to be available in the go.mod file, so that it is not removed by go mod tidy (used in hack/tools/bin/work/import-boss/main.go)
	_ "k8s.io/klog/v2"                   // import to be available in the go.mod file, so that it is not removed by go mod tidy (used in hack/tools/bin/work/import-boss/main.go)
	_ "sigs.k8s.io/yaml"                 // import to be available in the go.mod file, so that it is not removed by go mod tidy (used in hack/tools/bin/work/import-boss/main.go)
)

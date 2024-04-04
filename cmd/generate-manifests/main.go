/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"os"

	"github.com/gardener/cert-management/pkg/deployer/gen"
)

var version string

func main() {
	os.Exit(gen.GenerateWithArgs(os.Args[1:], ""))
}

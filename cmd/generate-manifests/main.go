/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"os"

	"github.com/gardener/cert-management/pkg/deployer"
)

func main() {
	deployer.GenerateManifestsCommand(os.Args[1:], "")
}

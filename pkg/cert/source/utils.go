/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package source

import (
	"github.com/gardener/controller-manager-library/pkg/resources"
)

func requireFinalizer(src resources.Object, cluster resources.Cluster) bool {
	return src.GetCluster() != cluster
}

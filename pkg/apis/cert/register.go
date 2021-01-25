/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//go:generate bash ../../../vendor/github.com/gardener/controller-manager-library/hack/generate-crds

package cert

const (
	// GroupName is the name of the certificate API group.
	GroupName = "cert.gardener.cloud"
)

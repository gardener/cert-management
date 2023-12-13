/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//go:generate sh -c "CONTROLLER_GEN=$CONTROLLER_GEN bash $CONTROLLER_MANAGER_LIB_HACK_DIR/generate-crds"

package cert

const (
	// GroupName is the name of the certificate API group.
	GroupName = "cert.gardener.cloud"
)

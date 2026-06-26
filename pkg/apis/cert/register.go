/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//go:generate sh -c "CONTROLLER_GEN=$CONTROLLER_GEN CONTROLLER_MANAGER_LIB_HACK_DIR=$CONTROLLER_MANAGER_LIB_HACK_DIR ../../../hack/generate-crds.sh"

package cert

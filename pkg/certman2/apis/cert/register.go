/*
 * SPDX-FileCopyrightText: Contributors to the Gardener project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//go:generate sh -c "CONTROLLER_GEN=$CONTROLLER_GEN bash $GARDENER_HACK_DIR/generate-crds.sh -p 'crd-' cert.gardener.cloud"

package cert

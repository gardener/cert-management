#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -eu

CONTROLLER_GEN=$CONTROLLER_GEN bash "$CONTROLLER_MANAGER_LIB_HACK_DIR/generate-crds"

# move `zz_generated_crds.go` to avoid dependencies to controller-manager-library in "pkg/apis" module.
# The mv step is a workaround for the controller-gen tool writing the embed .go into the source-dir.
source_dir="$(dirname "$0")/../pkg/apis/cert/crds"
destination_dir="$(dirname "$0")/../pkg/cert/crds"
mkdir -p "$destination_dir"
mv "$source_dir/zz_generated_crds.go" "$destination_dir"

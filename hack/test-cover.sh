#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

GARDENER_HACK_DIR=$(go list -m -f "{{.Dir}}" github.com/gardener/gardener)/hack

# Source the original script and pass all arguments
source "$GARDENER_HACK_DIR/test-cover.sh" "$@"

# Remove generated files from the coverage profile
# $COVERPROFILE_TMP and $COVERPROFILE are set in the sourced script
cat "$COVERPROFILE_TMP" | grep -vE "\.pb\.go|zz_generated|/pkg/client" > "$COVERPROFILE"
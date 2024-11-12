#!/usr/bin/env bash
# SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0


set -o errexit
set -o pipefail

source "$(dirname ${0})/common.sh" ''

touch "$SOURCE_PATH/dev/manifests.yaml"
touch "$SOURCE_PATH/dev/manifests-dnsrecords.yaml"
skaffold run "$@"

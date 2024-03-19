#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0


set -e

repo_dir="$(dirname "$0")/.."
source_dir="${repo_dir}/pkg/apis/cert/crds"
destination_dir="${repo_dir}/pkg/deployer/kubernetes/"

# Iterate through each YAML file in the source directory
for source_file in "$source_dir"/*.yaml; do
    if [ -f "$source_file" ]; then
        cp "$source_file" "$destination_dir"
    fi
done

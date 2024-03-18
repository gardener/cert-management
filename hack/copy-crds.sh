#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0


set -e

source_dir="$(dirname "$0")/../pkg/apis/cert/crds"
destination_dir="$(dirname "$0")/../pkg/deployer/kubernetes/"

# Function to update the metadata section and copy to destination
update_and_copy() {
    local source_file="$1"
    local dest_file="$destination_dir/$(basename "$source_file")"

    # Use awk to update the metadata and copy to destination
    awk '/^metadata:/ {
        print
        metadata_found = 1
        if ($0 == "metadata:") {
            print "  labels:"
            print "    helm.sh/chart: {{ include \"cert-management.chart\" . }}"
            print "    app.kubernetes.io/name: {{ include \"cert-management.name\" . }}"
            print "    app.kubernetes.io/instance: {{ .Release.Name }}"
            print "    app.kubernetes.io/managed-by: {{ .Release.Service }}"
        }
        next
    }
    metadata_found == 1 { metadata_found = 0 }
    {print}' "$source_file" > "$dest_file"
}

# Iterate through each YAML file in the source directory
for source_file in "$source_dir"/*.yaml; do
    if [ -f "$source_file" ]; then
        update_and_copy "$source_file"
    fi
done

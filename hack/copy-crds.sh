#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0


set -e

source_dir="$(dirname "$0")/../pkg/apis/cert/crds"
destination_dir="$(dirname "$0")/../charts/cert-management/templates/"

# Function to update the metadata section and copy to destination
update_and_copy() {
    local source_file="$1"
    local dest_file="$2"

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

# Function to add header and footer lines
add_header_and_footer() {
    local source_file="$1"
    local temp_file="$(mktemp)"

    # Add header, original content, and footer to a temporary file
    {
        if [[ "$source_file" == *"cert.gardener.cloud_issuers.yaml" ]]; then
            echo '{{- if .Values.createCRDs.issuers }}'
        else
            echo '{{- if .Values.createCRDs.certificates }}'
        fi
        cat "$source_file"
        echo '{{- end }}'
    } > "$temp_file"

    # Move the temporary file to the original source file
    mv "$temp_file" "$source_file"
}

# Iterate through each YAML file in the source directory
for source_file in "$source_dir"/*.yaml; do
    if [ -f "$source_file" ]; then
        dest_file="$destination_dir/$(basename "$source_file")"
        update_and_copy "$source_file" "$dest_file"
        add_header_and_footer "$dest_file"
    fi
done

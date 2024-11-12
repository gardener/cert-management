#!/bin/bash
# SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0


# Takes the content of a go.mod file and an array to add the extracted dependencies to.
extract_dependencies() {
    local go_mod=$1
    local dependencies=$2

    while IFS= read -r line; do
        dependency=$(echo "$line" | awk '{print $1}') # Splits the line by spaces and takes the first part omitting the version and the //indirect comment.
        eval "$dependencies+=('$dependency')"
    done <<< "$go_mod"
}

echo "🛜 Downloading the latest 'go.mod' from gardener/gardener..."

# Only the dependencies in a `go.mod` file are indented with a tab.
certman_go_mod=$(grep -P '^\t' go.mod) # Uses Perl-style regular expressions to match a tab at the beginning of a line.
gardener_go_mod=$(curl -s https://raw.githubusercontent.com/gardener/gardener/refs/heads/master/go.mod | grep -P '^\t')

certman_dependencies=()
gardener_dependencies=()

extract_dependencies "$certman_go_mod" certman_dependencies
extract_dependencies "$gardener_go_mod" gardener_dependencies

echo "📜 Found ${#certman_dependencies[@]} cert-manager dependencies."
echo "🚜 Found ${#gardener_dependencies[@]} gardener dependencies."

# Extract the intersection of the two arrays by iterating over them in a nested fashion.
common_dependencies=()

for certman_dependency in "${certman_dependencies[@]}"; do
    for gardener_dependency in "${gardener_dependencies[@]}"; do
        if [[ "$certman_dependency" == "$gardener_dependency" ]]; then
            common_dependencies+=("$certman_dependency")
            break # Continue with the next element of the outer loop.
        fi
    done
done

echo "☯️ Found ${#common_dependencies[@]} common dependencies."

ignore_deps=$(printf ',"%s"' "${common_dependencies[@]}") # Add a comma to the beginning of each element and concatenate them.
ignore_deps="[${ignore_deps:1}]" # Remove the leading comma and wrap the string in square brackets to format it as a JSON array.
clipboard_content=$(echo "$ignore_deps" | jq) # Format the JSON array as a string to copy it to the clipboard.

printf '\n'
echo "{\"ignoreDeps\":$ignore_deps}" | jq # Output the full JSON object to the shell.
printf '\n'

pbcopy <<< "$clipboard_content" # Copy the formatted JSON array to the clipboard.

echo "📋 Please paste the value of the generated 'ignoreDeps' into the 'renovate.json5' configuration file. The content has been copied to your clipboard."
exit 0

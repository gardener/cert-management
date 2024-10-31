#!/bin/bash

confirm() {
    read -p "$1 (y/n): " response
    case $response in
        [Yy]* ) return 0;; # User responded with 'yes'
        [Nn]* ) return 1;; # User responded with 'no'
        * ) echo "😤 Please answer y or n." && confirm "$1";; # Invalid input, ask again.
    esac
}

# Takes the content of a go.mod file and an array to add the extracted dependencies to.
extract_dependencies() {
    local go_mod=$1
    local dependencies=$2

    while IFS= read -r line; do
        dependency=$(echo "$line" | awk '{print $1}') # Splits the line by spaces and takes the first part omitting the version and the //indirect comment.
        eval "$dependencies+=('$dependency')"
    done <<< "$go_mod"
}

if ! confirm "🤔 This will override the field 'ignoreDeps' in the file 'renovate.json'. Do you want to continue?"; then
    echo "🛑 Cancelled."
    exit 0
fi

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
echo "✍️ Overriding the field 'ignoreDeps' in the file 'renovate.json'..."

ignore_deps=$(printf ',"%s"' "${common_dependencies[@]}") # Add a comma to the beginning of each element and concatenate them.
ignore_deps="[${ignore_deps:1}]" # Remove the leading comma and wrap the string in square brackets.

# Use `jq` to override the field `ignoreDeps` in the file `renovate.json`.
jq --argjson ignoreDeps "$ignore_deps" '.ignoreDeps = $ignoreDeps' renovate.json > renovate.json.tmp && mv renovate.json.tmp renovate.json

echo '🎉 Done!'
exit 0

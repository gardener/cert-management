#!/usr/bin/env bash

set -o errexit
set -o pipefail

source "$(dirname ${0})/common.sh" ''

touch "$SOURCE_PATH/dev/manifests.yaml"
skaffold run

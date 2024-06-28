#!/usr/bin/env bash

set -e

echo "> Format"

goimports -l -w $@

# Format import order only after files have been formatted by imports.
echo "> Format Import Order"

goimports_reviser_opts=${GOIMPORTS_REVISER_OPTIONS:-""}

for p in "$@" ; do
  goimports-reviser $goimports_reviser_opts -recursive $p
done
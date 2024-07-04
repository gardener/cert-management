#!/usr/bin/env bash

set -o errexit
set -o pipefail

source "$(dirname ${0})/common.sh" ''

cd "$SOURCE_PATH/test/functional"

FUNCTEST_CONFIG=functest-config-kind.yaml DNS_KUBECONFIG=$KUBECONFIG DNS_DOMAIN=functest.certman.kind USE_DNSRECORDS=$USE_DNSRECORDS ginkgo --output-interceptor-mode=none --succinct

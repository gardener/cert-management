#!/usr/bin/env bash
# SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0


set -o errexit
set -o pipefail

source "$(dirname ${0})/common.sh" ''

cd "$SOURCE_PATH/test/functional"

FUNCTEST_CONFIG=functest-config-kind.yaml DNS_KUBECONFIG=$KUBECONFIG DNS_DOMAIN=functest.certman.kind USE_DNSRECORDS=$USE_DNSRECORDS ginkgo --succinct

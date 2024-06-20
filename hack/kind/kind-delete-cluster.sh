#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail

source $(dirname ${0})/common.sh ''

export KUBECONFIG=${SOURCE_PATH}/dev/kind-kubeconfig.yaml

kind delete cluster --name cert-management

rm -f $KUBECONFIG

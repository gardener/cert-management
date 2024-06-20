#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

# For the check step concourse will set the following environment variables:
# SOURCE_PATH - path to component repository root directory.
if [[ -z "${SOURCE_PATH}" ]]; then
  export SOURCE_PATH="$(readlink -f "$(dirname ${0})/../..${1}")"
else
  export SOURCE_PATH="$(readlink -f ${SOURCE_PATH})"
fi

mkdir -p ${SOURCE_PATH}/dev
export KUBECONFIG=${SOURCE_PATH}/dev/kind-kubeconfig.yaml
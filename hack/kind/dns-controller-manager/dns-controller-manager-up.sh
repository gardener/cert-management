#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail

VERSION=v0.18.6

source $(dirname ${0})/../common.sh /..

target_dir=${SOURCE_PATH}/dev/external-dns-management-${VERSION#v}

download_external_dns_management_helm_charts()
{
  if [ -d $target_dir ]; then
    echo "charts already at $target_dir"
    return
  fi

  wget -qO- https://github.com/gardener/external-dns-management/archive/refs/tags/$VERSION.tar.gz | tar xvz -C ${SOURCE_PATH}/dev external-dns-management-${VERSION#v}/charts/external-dns-management
}

install_dns_controller_manager()
{
  kubectl get ns certman-support  >/dev/null 2>&1 || kubectl create ns certman-support
  helm template $target_dir/charts/external-dns-management -n certman-support \
    --set configuration.identifier="host-$(hostname)" \
    --set createCRDs=true \
    --set vpa.enabled=false \
    | kubectl apply -f -
}

download_external_dns_management_helm_charts
install_dns_controller_manager
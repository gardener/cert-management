#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail

source $(dirname ${0})/../common.sh /..

# dummy password
PASSWORD="123456"
PASSWORD_BASE64=$(echo -n $PASSWORD | base64 -w0)

wait_for_service()
{
  timeout=15

  echo looking up IP address for knot-dns service
  for ((i=0; i<$timeout; i++)); do
    set +e
    SERVICE_IP_ADDRESS=$(kubectl get svc knot-dns -n certman-support '-ojsonpath={.spec.clusterIP}' 2> /dev/null)
    set -e
    if [ -n "$SERVICE_IP_ADDRESS" ]; then
      echo
      echo "knot-dns service IP address: $SERVICE_IP_ADDRESS"
      return 0
    fi
    echo -n .
    sleep 1
  done
  echo failed
  return 1
}

kubectl apply -f $(dirname ${0})/crd-dnsprovider.yaml
kubectl get ns certman-support  >/dev/null 2>&1 || kubectl create ns certman-support
kubectl apply -f $(dirname ${0})/knot-dns-service.yaml
wait_for_service
kubectl apply -f <(sed -e "s/#secret-injection/$PASSWORD_BASE64/g" $(dirname ${0})/knot-dns-certman-support.yaml.template | \
                   sed -e "s/#server-injection/$SERVICE_IP_ADDRESS/g")

# patch coredns on all clusters
$(dirname ${0})/patch-coredns.sh $SERVICE_IP_ADDRESS &

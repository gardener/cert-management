#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail

source $(dirname ${0})/../common.sh /..

kubectl apply -f ${SOURCE_PATH}/pkg/apis/cert/crds/cert.gardener.cloud_issuers.yaml

cat  << EOF | kubectl apply -f -
apiVersion: cert.gardener.cloud/v1alpha1
kind: Issuer
metadata:
  name: local-issuer
  namespace: default
spec:
  acme:
    server: https://localhost:5443/dir
    email: some.user@certman.kind
    autoRegistration: true
    precheckNameservers:
    - 127.0.0.1:5053
EOF

cat  << EOF > ${SOURCE_PATH}/dev/source-lego-env.sh
export LEGO_CA_CERTIFICATES=${SOURCE_PATH}/dev/pebble-cert.pem
export LEGO_CA_SYSTEM_CERT_POOL=true
EOF

echo For running cert-controller-manager outside of the kind cluster,
echo please add these environment variables:
echo
cat ${SOURCE_PATH}/dev/source-lego-env.sh
echo
echo or run "'"source ${SOURCE_PATH}/dev/source-lego-env.sh"'"
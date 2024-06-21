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
  name: kind-issuer
  namespace: default
spec:
  acme:
    server: https://acme.certman-support.svc.cluster.local/dir
    email: some.user@certman.kind
    autoRegistration: true
    precheckNameservers:
    - 10.96.0.10:53 # service kube-system/kube-dns (coredns)
EOF

#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -e

REPO_ROOT="$(dirname "$0")/.."
KC="${REPO_ROOT}/dev/kind-kubeconfig.yaml"
KUBECTL="${1:-kubectl}"

echo "==> Creating CA secret..."
CA_PEM="$(openssl req -x509 -newkey rsa:2048 -keyout /dev/null -out /dev/stdout -days 1 -subj '/CN=test-ca' -nodes 2>/dev/null)"
KUBECONFIG="$KC" "$KUBECTL" create secret generic test-cainjector-secret -n default \
  --from-literal=ca.crt="$CA_PEM" --dry-run=client -o yaml | KUBECONFIG="$KC" "$KUBECTL" apply -f -
KUBECONFIG="$KC" "$KUBECTL" annotate secret test-cainjector-secret -n default \
  cert.gardener.cloud/allow-direct-injection=true --overwrite

printf '%s\n' \
  'apiVersion: apiregistration.k8s.io/v1' \
  'kind: APIService' \
  'metadata:' \
  '  name: v1alpha1.cainjector-test.sap.com' \
  '  annotations:' \
  '    cert.gardener.cloud/inject-ca-from-secret: default/test-cainjector-secret' \
  'spec:' \
  '  group: cainjector-test.sap.com' \
  '  groupPriorityMinimum: 1000' \
  '  versionPriority: 15' \
  '  service:' \
  '    name: api' \
  '    namespace: default' \
  '  version: v1alpha1' \
  | KUBECONFIG="$KC" "$KUBECTL" apply -f -

echo "==> Waiting for initial caBundle injection (up to 60s)..."
i=0
while [ "$i" -lt 60 ]; do
  BUNDLE="$(KUBECONFIG="$KC" "$KUBECTL" get apiservice v1alpha1.cainjector-test.sap.com \
    -o jsonpath='{.spec.caBundle}' 2>/dev/null)"
  [ -n "$BUNDLE" ] && break
  sleep 1; i=$((i+1))
done
[ "$i" -lt 60 ] || { echo "ERROR: caBundle not injected within 60s — is the controller running? (make dev in another terminal)"; exit 1; }
echo "==> Initial injection confirmed."

echo "==> Simulating CA rotation..."
OLD_BUNDLE="$BUNDLE"
NEW_PEM="$(openssl req -x509 -newkey rsa:2048 -keyout /dev/null -out /dev/stdout -days 1 -subj '/CN=rotated-ca' -nodes 2>/dev/null)"
KUBECONFIG="$KC" "$KUBECTL" create secret generic test-cainjector-secret -n default \
  --from-literal=ca.crt="$NEW_PEM" --dry-run=client -o yaml | KUBECONFIG="$KC" "$KUBECTL" apply -f -
KUBECONFIG="$KC" "$KUBECTL" annotate secret test-cainjector-secret -n default \
  cert.gardener.cloud/allow-direct-injection=true --overwrite

echo "==> Waiting for caBundle to reflect the rotated CA (up to 60s)..."
i=0
while [ "$i" -lt 60 ]; do
  NEW="$(KUBECONFIG="$KC" "$KUBECTL" get apiservice v1alpha1.cainjector-test.sap.com \
    -o jsonpath='{.spec.caBundle}' 2>/dev/null)"
  [ "$NEW" != "$OLD_BUNDLE" ] && [ -n "$NEW" ] && break
  sleep 1; i=$((i+1))
done
[ "$i" -lt 60 ] || { echo "ERROR: caBundle was not updated after CA rotation within 60s"; exit 1; }
echo "==> caBundle updated after CA rotation — OK"

echo "==> Cleaning up..."
KUBECONFIG="$KC" "$KUBECTL" delete apiservice v1alpha1.cainjector-test.sap.com 2>/dev/null || true
KUBECONFIG="$KC" "$KUBECTL" delete secret test-cainjector-secret -n default 2>/dev/null || true
echo "==> All checks passed."

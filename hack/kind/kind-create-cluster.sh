#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail

source $(dirname ${0})/common.sh ''

setup_containerd_registry_mirror() {
  NODE=$1
  UPSTREAM_HOST=$2
  UPSTREAM_SERVER=$3
  MIRROR_HOST=$4

  echo "[${NODE}] Setting up containerd registry mirror for host ${UPSTREAM_HOST}.";
  REGISTRY_DIR="/etc/containerd/certs.d/${UPSTREAM_HOST}"
  docker exec "${NODE}" mkdir -p "${REGISTRY_DIR}"
  cat <<EOF | docker exec -i "${NODE}" cp /dev/stdin "${REGISTRY_DIR}/hosts.toml"
server = "${UPSTREAM_SERVER}"

[host."${MIRROR_HOST}"]
  capabilities = ["pull", "resolve"]
EOF
}

echo "### creating/updating kind cluster cert-management"

# only create cluster if not existing
kind get clusters | grep cert-management &> /dev/null || \
  kind create cluster \
    --name cert-management \
    --config <(cat <<EOF
apiVersion: kind.x-k8s.io/v1alpha4
kind: Cluster
nodes:
- role: control-plane
  image: kindest/node:v1.30.0
  extraMounts:
  - hostPath: ${SOURCE_PATH}/dev/local-registry
    containerPath: /var/local-registry
  extraPortMappings:
  - containerPort: 30443
    hostPort: 5443
    protocol: TCP
  - containerPort: 30444
    hostPort: 5444
    protocol: TCP
  - containerPort: 30053
    hostPort: 5053
    protocol: TCP
  - containerPort: 30053
    hostPort: 5053
    protocol: UDP

containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry]
    config_path = "/etc/containerd/certs.d"

EOF
)

# Deploy registry caches
kubectl apply -k "$SOURCE_PATH/hack/kind/registry" --server-side
kubectl wait --for=condition=available deployment -l app=registry -n registry --timeout 5m

registryHostname=cert-management-control-plane
# Configure containerd to pull images from registry caches
for node in $(kind get nodes --name="cert-management"); do
  setup_containerd_registry_mirror $node "ghcr.io" "https://ghcr.io" "http://${registryHostname}:5005"
  setup_containerd_registry_mirror $node "registry.k8s.io" "https://registry.k8s.io" "http://${registryHostname}:5006"
  setup_containerd_registry_mirror $node "europe-docker.pkg.dev" "https://europe-docker.pkg.dev" "http://${registryHostname}:5008"
  setup_containerd_registry_mirror $node "docker.io" "http://docker.io" "http://${registryHostname}:5009"
done



echo "### To access $clusterName cluster, use:"
echo "export KUBECONFIG=$KUBECONFIG"
echo ""

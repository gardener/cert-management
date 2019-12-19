#!/usr/bin/env bash
#
# Copyright 2018 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e
SCRIPT_BASEDIR=$(dirname "$0")
ROOTDIR=../..
echo ROOTDIR: $ROOTDIR

cd $SCRIPT_BASEDIR

FUNCTEST_CONFIG=functest-config.yaml
RUN_CONTROLLER=true

usage()
{
    cat <<EOM
Usage:
Runs functional tests for cert-management for all issuers provided in default-functest-config.yaml.
A dns-controller MUST be running and a DNS provider configured to deal with the given domains.

./run.sh [-f <functest-config.yaml>] [-r|--reuse] [-l] [-v] [-k|--keep] [--no-controller]
         [--dns] [--dns-domain <domain>]
         [-- <options> <for> <ginkgo>]

Options:
    -r | --reuse           reuse existing kind cluster
    -k | --keep            keep kind cluster after run for reuse or inspection
    -l                     use local kube-apiserver and etcd (i.e. no kind cluster)
    -v                     verbose output of script (not test itself)
    -f <config.yaml>       path to functest configuration file (defaults to $FUNCTEST_CONFIG)
    --no-controller        do not start the cert-controller-manager
    --dns                  kubeconfig for writing temporary DNS entries of challenges (default to $DNS_KUBECONFIG or $KUBECONFIG)
    --dns-domain <domain>  DNS domain suffix to use for certificates (must have a DNS provider)
For options of ginkgo run:
    ginkgo -h

Example: ./run.sh -r -k -- -dryRun
EOM
}

while [ "$1" != "" ]; do
    case $1 in
        -r | --restart )   shift
                           NOBOOTSTRAP=true
                           ;;
        -v )               shift
                           VERBOSE=true
                           ;;
        -l )               shift
                           LOCAL_APISERVER=true
                           ;;
        -k | --keep )      shift
                           KEEP_CLUSTER=true
                           ;;
        -f )               shift
                           FUNCTEST_CONFIG=$1
                           shift
                           ;;
        --no-controller )  shift
                           RUN_CONTROLLER=false
                           ;;
        --dns )            shift
                           DNS_KUBECONFIG=$1
                           shift
                           ;;
        --dns-domain )     shift
                           DNS_DOMAIN=$1
                           shift
                           ;;
        -- )               shift
                           break
                           ;;
        * )                usage
                           exit 1
    esac
done

trapHandler()
{
  if [[ -n "$PID_APISERVER" ]]; then
    kill $PID_APISERVER
  fi

  if [[ -n "$PID_ETCD" ]]; then
    kill $PID_ETCD
  fi

  if [[ -n "$PID_CONTROLLER" ]]; then
    kill $PID_CONTROLLER
  fi
}

trap trapHandler SIGINT SIGTERM EXIT

if [ "$LOCAL_APISERVER" == "" ]; then
  docker version > /dev/null || (echo "Local Docker installation needed" && exit 1)
fi

if [ "$VERBOSE" != "" ]; then
  set -x
fi


if [ "$NOBOOTSTRAP" == "" ] && [ "$LOCAL_APISERVER" == "" ]; then
  echo Starting Kubernetes IN Docker...

  # prepare Kubernetes IN Docker - local clusters for testing Kubernetes
  go install -mod=vendor sigs.k8s.io/kind

  # delete old cluster
  kind delete cluster --name integration || true

  # create K8n cluster in docker
  kind create cluster --name integration
fi


if [ "$LOCAL_APISERVER" != "" ]; then
  echo using local kube-apiserver and etcd

  # download kube-apiserver, etcd, and kubectl executables from kubebuilder release
  KUBEBUILDER_VERSION=1.0.8
  ARCH=$(go env GOARCH)
  GOOS=$(go env GOOS)
  KUBEBUILDER_BIN_DIR=$(realpath -m kubebuilder_${KUBEBUILDER_VERSION}_${GOOS}_${ARCH}/bin)
  if [ ! -d $KUBEBUILDER_BIN_DIR ]; then
    curl -Ls https://github.com/kubernetes-sigs/kubebuilder/releases/download/v${KUBEBUILDER_VERSION}/kubebuilder_${KUBEBUILDER_VERSION}_${GOOS}_${ARCH}.tar.gz | tar xz
  fi
  export PATH=$KUBEBUILDER_BIN_DIR:$PATH
  mkdir -p $KUBEBUILDER_BIN_DIR/../var

  # starting etcd
  echo Starting Etcd
  rm -rf default.etcd
  if [ "$VERBOSE" != "" ]; then
    $KUBEBUILDER_BIN_DIR/etcd &
  else
    $KUBEBUILDER_BIN_DIR/etcd >/dev/null 2>&1 &
  fi
  PID_ETCD=$!

  # starting kube-apiserver
  echo Starting Kube API Server
  if [ "$VERBOSE" != "" ]; then
    $KUBEBUILDER_BIN_DIR/kube-apiserver --etcd-servers http://localhost:2379 --cert-dir $KUBEBUILDER_BIN_DIR/../var &
  else
    $KUBEBUILDER_BIN_DIR/kube-apiserver --etcd-servers http://localhost:2379 --cert-dir $KUBEBUILDER_BIN_DIR/../var >/dev/null 2>&1 &
  fi
  PID_APISERVER=$!
  sleep 3

  # create local kubeconfig
  cat > /tmp/kubeconfig-local.yaml << EOF
apiVersion: v1
clusters:
- cluster:
    server: http://localhost:8080
  name: local
contexts:
- context:
    cluster: local
  name: local-ctx
current-context: local-ctx
kind: Config
preferences: {}
users: []
EOF
  export KUBECONFIG=/tmp/kubeconfig-local.yaml
else
  export KUBECONFIG=$(kind get kubeconfig-path --name="integration")
fi

kubectl cluster-info

if [ "$DNS_KUBECONFIG" == "" ]; then
  DNS_KUBECONFIG=$KUBECONFIG
fi
echo DNS_KUBECONFIG=$DNS_KUBECONFIG DNS_DOMAIN=$DNS_DOMAIN
kubectl --kubeconfig=$DNS_KUBECONFIG cluster-info

if [ "$?" != "0" ]; then
  echo dns cluster is not reachable
  exit 1
fi

if [ "$RUN_CONTROLLER" == "true" ]; then
  go build -mod=vendor -o $ROOTDIR/cert-controller-manager $ROOTDIR/cmd/cert-controller-manager
  $ROOTDIR/cert-controller-manager --dns $DNS_KUBECONFIG >/dev/null 2>&1 &
  PID_CONTROLLER=$!
fi

# install ginkgo
go install -mod=vendor github.com/onsi/ginkgo/ginkgo

GOFLAGS="-mod=vendor" FUNCTEST_CONFIG=$FUNCTEST_CONFIG DNS_KUBECONFIG=$DNS_KUBECONFIG DNS_DOMAIN=$DNS_DOMAIN ginkgo -p "$@"

RETCODE=$?

cd -

# cleanup
if [ "$KEEP_CLUSTER" == "" ] && [ "$LOCAL_APISERVER" == "" ]; then
  unset KUBECONFIG
  kind delete cluster --name integration
fi

exit $RETCODE
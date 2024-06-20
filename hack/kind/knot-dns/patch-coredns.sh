#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

knot_dns_ip=$1

echo patching deployment kube-system/coredns on cluster $(kubectl config current-context)

# patch configmap coredns to contain "import custom/*.override" and "import custom/*.server"
corefileOrg=$(kubectl -n kube-system get cm coredns '-ojsonpath={.data.Corefile}')
if ! [[ "$corefileOrg" == *"import custom/"* ]]; then
  tmp="${corefileOrg/%\}/}"
  tmp="${tmp//$'\n'/$'\n'  }"
  cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns
  namespace: kube-system
data:
  Corefile: |
    $tmp
      import custom/*.override
    }
    import custom/*.server
EOF
else
  echo coredns configmap already patched
fi

# create custom coredns configmap
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns-custom
  namespace: kube-system
data:
  additional.server: |
    certman.kind:53 {
      errors
      cache 30
      forward . $knot_dns_ip
    }
EOF

count=$(( $(kubectl -n kube-system get deploy coredns -oyaml '-ojsonpath={.spec.template.spec.volumes[?(@.name=="custom-config-volume")].name}' |wc -w) ))
if (( $count > 0 )); then
  kubectl -n kube-system delete pod -l k8s-app=kube-dns
else
  kubectl -n kube-system patch deploy coredns --patch-file $(dirname ${0})/patch-deployment-coredns.yaml
fi

echo ""

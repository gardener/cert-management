#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail

helm template charts/cert-management -n default \
    --set createCRDs.issuers=true \
    --set createCRDs.certificates=true \
    --set image.repository=local-skaffold/cert-controller-manager \
    --set image.tag=$SKAFFOLD_IMAGE_TAG \
    --set configuration.defaultIssuer=kind-issuer \
    --set configuration.caCertificates="$(cat dev/pebble-cert.pem)" \
    --set configuration.precheckAdditionalWait=30s \
    --set configuration.propagationTimeout=180s \
    --set configuration.poolResyncPeriod=30s \
    --set configuration.issuerDefaultPoolSize=20 \
    > dev/manifests.yaml

helm template charts/cert-management -n default \
    --set createCRDs.issuers=true \
    --set createCRDs.certificates=true \
    --set image.repository=local-skaffold/cert-controller-manager \
    --set image.tag=$SKAFFOLD_IMAGE_TAG \
    --set configuration.defaultIssuer=kind-issuer \
    --set configuration.caCertificates="$(cat dev/pebble-cert.pem)" \
    --set configuration.precheckAdditionalWait=30s \
    --set configuration.propagationTimeout=180s \
    --set configuration.poolResyncPeriod=15s \
    --set configuration.issuerPoolResyncPeriod=30s \
    --set configuration.issuerDefaultPoolSize=10 \
    --set configuration.useDnsrecords=true \
    > dev/manifests-dnsrecords.yaml

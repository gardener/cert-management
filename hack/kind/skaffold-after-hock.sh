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
    --set image.tag=$SKAFFOLD_IMAGE_TAG \
    --set configuration.defaultIssuer=kind-issuer \
    --set configuration.caCertificates="$(cat dev/pebble-cert.pem)" \
    > dev/manifests.yaml

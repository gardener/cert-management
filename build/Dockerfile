# SPDX-FileCopyrightText: 2018 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

#############      builder       #############
FROM eu.gcr.io/gardener-project/3rd/golang:1.16.6 AS builder

WORKDIR /build
COPY . .

RUN make release

############# base
FROM eu.gcr.io/gardener-project/3rd/alpine:3.13.5 AS base

#############      cert-controller-manager     #############
FROM base AS cert-controller-manager

RUN addgroup -S app && adduser -S -G app app
WORKDIR /
COPY --from=builder /build/cert-controller-manager /cert-controller-manager
USER app

ENTRYPOINT ["/cert-controller-manager"]

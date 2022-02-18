# SPDX-FileCopyrightText: 2018 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

#############      builder       #############
FROM golang:1.17.7 AS builder

WORKDIR /build
COPY . .

RUN make release

############# base
FROM alpine:3.15.0 AS base

#############      cert-controller-manager     #############
FROM base AS cert-controller-manager

RUN addgroup -S app && adduser -S -G app app
WORKDIR /
COPY --from=builder /build/cert-controller-manager /cert-controller-manager
USER app

ENTRYPOINT ["/cert-controller-manager"]

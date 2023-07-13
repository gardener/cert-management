# SPDX-FileCopyrightText: 2018 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

#############      builder       #############
FROM golang:1.20.6 AS builder

WORKDIR /build
COPY . .

RUN make release

############# base
FROM gcr.io/distroless/static-debian11:nonroot AS base

#############      cert-controller-manager     #############
FROM base AS cert-controller-manager

WORKDIR /
COPY --from=builder /build/cert-controller-manager /cert-controller-manager

ENTRYPOINT ["/cert-controller-manager"]

# SPDX-FileCopyrightText: 2018 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

#############      builder       #############
FROM golang:1.24.5 AS builder

WORKDIR /build

# Copy go mod and sum files
COPY go.mod go.sum ./
# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

COPY . .

RUN make release

############# base
FROM gcr.io/distroless/static-debian12:nonroot AS base

#############      cert-controller-manager     #############
FROM base AS cert-controller-manager

WORKDIR /
COPY --from=builder /build/cert-controller-manager /cert-controller-manager

ENTRYPOINT ["/cert-controller-manager"]

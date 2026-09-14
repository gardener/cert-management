# SPDX-FileCopyrightText: Contributors to the Gardener project
#
# SPDX-License-Identifier: Apache-2.0

#############      builder       #############
FROM --platform=$BUILDPLATFORM golang:1.27.1@sha256:f44f6e88636cfb311f9ebace870ded69d943f227bb3cb27d32ffd84ea18c43ea AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /build

# Copy go mod and sum files
COPY go.mod go.sum ./
COPY pkg/apis/go.mod pkg/apis/go.sum ./pkg/apis/
# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS=$TARGETOS GOARCH=$TARGETARCH make release

############# base
FROM gcr.io/distroless/static-debian13:nonroot AS base

WORKDIR /

#############      cert-controller-manager     #############
FROM base AS cert-controller-manager

COPY --from=builder /build/cert-controller-manager /cert-controller-manager

ENTRYPOINT ["/cert-controller-manager"]

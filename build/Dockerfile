# Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

#############      builder       #############
FROM golang:1.13.9 AS builder

WORKDIR /build
COPY . .

RUN make release

############# base
FROM alpine:3.11.3 AS base

#############      cert-controller-manager     #############
FROM base AS cert-controller-manager

RUN addgroup -S app && adduser -S -G app app
WORKDIR /
COPY --from=builder /build/cert-controller-manager /cert-controller-manager
USER app

ENTRYPOINT ["/cert-controller-manager"]

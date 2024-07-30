# SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

ENSURE_CONTROLLER_MANAGER_LIB_MOD := $(shell go get github.com/gardener/controller-manager-library@$$(go list -m -f "{{.Version}}" github.com/gardener/controller-manager-library))
CONTROLLER_MANAGER_LIB_HACK_DIR   := $(shell go list -m -f "{{.Dir}}" github.com/gardener/controller-manager-library)/hack
ENSURE_GARDENER_MOD               := $(shell go get github.com/gardener/gardener@$$(go list -m -f "{{.Version}}" github.com/gardener/gardener))
GARDENER_HACK_DIR                 := $(shell go list -m -f "{{.Dir}}" github.com/gardener/gardener)/hack
EXTERNAL_DNS_MAN_DIR              := $(shell go list -m -f "{{.Dir}}" github.com/gardener/external-dns-management)
REGISTRY                          := europe-docker.pkg.dev/gardener-project/public
EXECUTABLE                        := cert-controller-manager
EXECUTABLE2                       := certman2
REPO_ROOT                         := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
HACK_DIR                          := $(REPO_ROOT)/hack
PROJECT                           := github.com/gardener/cert-management
CERT_IMAGE_REPOSITORY             := $(REGISTRY)/cert-controller-manager
VERSION                           := $(shell cat VERSION)
IMAGE_TAG                         := $(VERSION)

#########################################
# Tools                                 #
#########################################

TOOLS_DIR := hack/tools
include $(GARDENER_HACK_DIR)/tools.mk

.PHONY: tidy
tidy:
	@go mod tidy
	@cp $(GARDENER_HACK_DIR)/sast.sh $(HACK_DIR)/sast.sh && chmod +xw $(HACK_DIR)/sast.sh
	@cp $(EXTERNAL_DNS_MAN_DIR)/pkg/apis/dns/crds/dns.gardener.cloud_dnsentries.yaml $(REPO_ROOT)/examples/11-dns.gardener.cloud_dnsentries.yaml

.PHONY: clean
clean:
	bash $(GARDENER_HACK_DIR)/clean.sh ./cmd/... ./pkg/...
	@rm -f $(REPO_ROOT)/pkg/apis/cert/crds/*

.PHONY: check
check: sast-report fastcheck

.PHONY: fastcheck
fastcheck: format $(GOIMPORTS) $(GOLANGCI_LINT) $(GO_ADD_LICENSE)
	@TOOLS_BIN_DIR="$(TOOLS_BIN_DIR)" bash $(CONTROLLER_MANAGER_LIB_HACK_DIR)/check.sh --golangci-lint-config=./.golangci.yaml ./cmd/... ./pkg/... ./test/...
	@bash $(GARDENER_HACK_DIR)/check-license-header.sh
	@echo "Running go vet..."
	@go vet ./cmd/... ./pkg/... ./test/...

.PHONY: add-license-headers
add-license-headers: $(GO_ADD_LICENSE)
	@bash $(GARDENER_HACK_DIR)/add-license-header.sh

.PHONY: format
format: $(GOIMPORTS) $(GOIMPORTSREVISER)
	@bash $(GARDENER_HACK_DIR)/format.sh ./cmd ./pkg ./test

.PHONY: build
build:
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(EXECUTABLE) \
	    -ldflags "-X main.version=$(VERSION)-$(shell git rev-parse HEAD)"\
	    ./cmd/cert-controller-manager

.PHONY: build-local
build-local:
	@CGO_ENABLED=0 go build -o $(EXECUTABLE) \
	    -ldflags "-X main.version=$(VERSION)-$(shell git rev-parse HEAD)"\
	    ./cmd/cert-controller-manager
	@CGO_ENABLED=0 go build -o $(EXECUTABLE2) \
	    -ldflags "-X main.version=$(VERSION)-$(shell git rev-parse HEAD)"\
	    ./cmd/certman2


.PHONY: release
release:
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(EXECUTABLE) \
	    -a \
	    -ldflags "-w -X main.version=$(VERSION)" \
	    ./cmd/cert-controller-manager

.PHONY: test
test: $(GINKGO)
	$(GINKGO) -r ./pkg

.PHONY: test-integration
test-integration: $(REPORT_COLLECTOR) $(SETUP_ENVTEST)
	@bash $(GARDENER_HACK_DIR)/test-integration.sh ./test/integration/...

.PHONY: test-cov
test-cov:
	@bash $(GARDENER_HACK_DIR)/test-cover.sh $(shell go list ./pkg/... | grep -v /pkg/client) ./cmd/...

.PHONY: generate
generate: $(VGOPATH) $(CONTROLLER_GEN)
	@GARDENER_HACK_DIR=$(GARDENER_HACK_DIR) VGOPATH=$(VGOPATH) REPO_ROOT=$(REPO_ROOT) ./hack/generate-code
	@CONTROLLER_MANAGER_LIB_HACK_DIR=$(CONTROLLER_MANAGER_LIB_HACK_DIR) CONTROLLER_GEN=$(shell realpath $(CONTROLLER_GEN)) go generate ./pkg/apis/cert/...
	@./hack/copy-crds.sh
	@GARDENER_HACK_DIR=$(GARDENER_HACK_DIR) VGOPATH=$(VGOPATH) REPO_ROOT=$(REPO_ROOT) CONTROLLER_GEN=$(shell realpath $(CONTROLLER_GEN)) go generate ./pkg/certman2/apis/cert/...
	@go fmt ./pkg/...

.PHONY: generate-renovate-ignore-deps
generate-renovate-ignore-deps:
	@./hack/generate-renovate-ignore-deps.sh

.PHONY: docker-images
docker-images:
	@docker build -t $(CERT_IMAGE_REPOSITORY):$(IMAGE_TAG) -t $(CERT_IMAGE_REPOSITORY):latest -f Dockerfile --target cert-controller-manager .

.PHONY: kind-up ## create kind cluster with knot-dns and pebble
kind-up: $(KIND) $(HELM)
	@hack/kind/kind-create-cluster.sh
	@hack/kind/knot-dns/knot-dns-up.sh
	@hack/kind/pebble/pebble-up.sh
	@hack/kind/dns-controller-manager/dns-controller-manager-up.sh

.PHONY: kind-down
kind-down: $(KIND)
	@hack/kind/kind-delete-cluster.sh

.PHONY: local-issuer-up
local-issuer-up:
	@hack/kind/local-issuer/local-issuer-up.sh

.PHONY: local-issuer-down
local-issuer-down:
	@hack/kind/local-issuer/local-issuer-down.sh

.PHONY: kind-issuer-up
kind-issuer-up:
	@hack/kind/certman/issuer-up.sh

.PHONY: kind-issuer-down
kind-issuer-down:
	@hack/kind/certman/issuer-down.sh

.PHONY: skaffold-run
skaffold-run: $(SKAFFOLD)
	@hack/kind/skaffold-run.sh

.PHONY: skaffold-run-dnsrecords
skaffold-run-dnsrecords: $(SKAFFOLD)
	@hack/kind/skaffold-run.sh -p dnsrecords

.PHONY: certman-up
certman-up: $(SKAFFOLD) $(HELM) kind-issuer-up skaffold-run

.PHONY: certman-down
certman-down:
	@hack/kind/certman/issuer-down.sh
	@hack/kind/certman/certman-down.sh

.PHONY: certman-dnsrecords-up
certman-dnsrecords-up: $(SKAFFOLD) $(HELM) kind-issuer-up skaffold-run-dnsrecords

.PHONY: certman-dnsrecords-down
certman-dnsrecords-down:
	@hack/kind/certman/issuer-down.sh
	@hack/kind/certman/certman-down.sh

.PHONY: test-functional-local
test-functional-local: $(GINKGO)
	@hack/kind/test-functional-local.sh

.PHONY: test-functional-local-dnsrecords
test-functional-local-dnsrecords: $(GINKGO)
	@USE_DNSRECORDS=true hack/kind/test-functional-local.sh

.PHONY: test-e2e-local
test-e2e-local: kind-up certman-up test-functional-local certman-dnsrecords-up test-functional-local-dnsrecords

.PHONY: sast
sast: $(GOSEC)
	@./hack/sast.sh

.PHONY: sast-report
sast-report: $(GOSEC)
	@./hack/sast.sh --gosec-report true

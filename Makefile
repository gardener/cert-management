# SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

ENSURE_CONTROLLER_MANAGER_LIB_MOD := $(shell go get github.com/gardener/controller-manager-library@$$(go list -m -f "{{.Version}}" github.com/gardener/controller-manager-library))
CONTROLLER_MANAGER_LIB_HACK_DIR   := $(shell go list -m -f "{{.Dir}}" github.com/gardener/controller-manager-library)/hack
REGISTRY                          := europe-docker.pkg.dev/gardener-project/public
EXECUTABLE                        := cert-controller-manager
REPO_ROOT                         := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
PROJECT                           := github.com/gardener/cert-management
CERT_IMAGE_REPOSITORY             := $(REGISTRY)/cert-controller-manager
VERSION                           := $(shell cat VERSION)
IMAGE_TAG                         := $(VERSION)

#########################################
# Tools                                 #
#########################################

TOOLS_DIR := hack/tools
include $(CONTROLLER_MANAGER_LIB_HACK_DIR)/tools.mk

.PHONY: tidy
tidy:
	@go mod tidy

.PHONY: check
check: format $(GOIMPORTS) $(GOLANGCI_LINT)
	@TOOLS_BIN_DIR="$(TOOLS_DIR)/bin" bash $(CONTROLLER_MANAGER_LIB_HACK_DIR)/check.sh --golangci-lint-config=./.golangci.yaml ./cmd/... ./pkg/... ./test/...
	@echo "Running go vet..."
	@go vet ./cmd/... ./pkg/... ./test/...

.PHONY: format
format:
	@go fmt ./cmd/... ./pkg/... ./test/...

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


.PHONY: release
release:
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(EXECUTABLE) \
	    -a \
	    -ldflags "-w -X main.version=$(VERSION)" \
	    ./cmd/cert-controller-manager

.PHONY: test
test: $(GINKGO)
	$(GINKGO) -r ./pkg

.PHONY: clean
clean:
	@rm -rf $(REPO_ROOT)/examples/deployment/*

.PHONY: generate
generate: clean $(VGOPATH) $(CONTROLLER_GEN)
	@CONTROLLER_MANAGER_LIB_HACK_DIR=$(CONTROLLER_MANAGER_LIB_HACK_DIR) VGOPATH=$(VGOPATH) REPO_ROOT=$(REPO_ROOT) ./hack/generate-code
	@CONTROLLER_MANAGER_LIB_HACK_DIR=$(CONTROLLER_MANAGER_LIB_HACK_DIR) CONTROLLER_GEN=$(shell realpath $(CONTROLLER_GEN)) go generate ./pkg/apis/cert/...
	@go generate ./hack/deployer
	@./hack/copy-crds.sh
	@go fmt ./pkg/...

.PHONY: docker-images
docker-images:
	@docker build -t $(CERT_IMAGE_REPOSITORY):$(IMAGE_TAG) -t $(CERT_IMAGE_REPOSITORY):latest -f Dockerfile --target cert-controller-manager .

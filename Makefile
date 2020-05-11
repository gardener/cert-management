REGISTRY              := eu.gcr.io/gardener-project
EXECUTABLE            := cert-controller-manager
PROJECT               := github.com/gardener/cert-management
CERT_IMAGE_REPOSITORY := $(REGISTRY)/cert-controller-manager
VERSION               := $(shell cat VERSION)
IMAGE_TAG             := $(VERSION)


.PHONY: revendor
revendor:
	@GO111MODULE=on go mod vendor
	@GO111MODULE=on go mod tidy

.PHONY: check
check:
	@.ci/check

.PHONY: build
build:
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -o $(EXECUTABLE) \
        -mod=vendor \
	    -ldflags "-X main.version=$(VERSION)-$(shell git rev-parse HEAD)"\
	    ./cmd/cert-controller-manager

.PHONY: build-local
build-local:
	@CGO_ENABLED=0 GO111MODULE=on go build -o $(EXECUTABLE) \
	    -mod=vendor \
	    -ldflags "-X main.version=$(VERSION)-$(shell git rev-parse HEAD)"\
	    ./cmd/cert-controller-manager


.PHONY: release
release:
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -o $(EXECUTABLE) \
	    -a \
	    -mod=vendor \
	    -ldflags "-w -X main.version=$(VERSION)" \
	    ./cmd/cert-controller-manager

.PHONY: test
test:
	GO111MODULE=on go test -mod=vendor ./pkg/...

.PHONY: generate
generate:
	@./hack/generate-code

.PHONY: docker-images
docker-images:
	@docker build -t $(CERT_IMAGE_REPOSITORY):$(IMAGE_TAG) -t $(CERT_IMAGE_REPOSITORY):latest -f build/Dockerfile --target cert-controller-manager .

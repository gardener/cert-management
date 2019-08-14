EXECUTABLE=cert-controller-manager
PROJECT=github.com/gardener/cert-management
VERSION=$(shell cat VERSION)


.PHONY: local-build build release test alltests


build:
	GOOS=linux GOARCH=amd64 go build -o $(EXECUTABLE) \
	    -ldflags "-X main.Version=$(VERSION)-$(shell git rev-parse HEAD)"\
	    ./cmd/cert-controller-manager


local-build:
	go build -o $(EXECUTABLE) \
	    -ldflags "-X main.Version=$(VERSION)-$(shell git rev-parse HEAD)"\
	    ./cmd/cert-controller-manager


release:
	GOOS=linux GOARCH=amd64 go build -o $(EXECUTABLE) \
	    -ldflags "-X main.Version=$(VERSION) \
	    ./cmd/cert-controller-manager

test:
	go test ./pkg/...
#	@echo ----- Skipping long running integration tests, use \'make alltests\' to run all tests -----
#	test/integration/run.sh $(kindargs) -- -skip Many $(args)

alltests:
	go test ./pkg/...
#	test/integration/run.sh $(kindargs) -- $(args)

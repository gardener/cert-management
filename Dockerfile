FROM golang:1.12.8
WORKDIR /go/src/github.com/gardener/cert-management/
RUN go get -u github.com/golang/dep/cmd/dep
COPY . .
RUN dep ensure
RUN CGO_ENABLED=0 GOOS=linux go build -a -o cert-controller-manager -ldflags "-X main.Version=$(cat VERSION)-$(git rev-parse HEAD)" ./cmd/cert-controller-manager

FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/
COPY --from=0 /go/src/github.com/gardener/cert-management/cert-controller-manager .
ENTRYPOINT ["./cert-controller-manager"]

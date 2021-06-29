module github.com/gardener/cert-management

go 1.16

require (
	github.com/ahmetb/gen-crd-api-reference-docs v0.2.0
	github.com/emicklei/go-restful v2.11.1+incompatible // indirect
	github.com/gardener/controller-manager-library v0.2.1-0.20210628114606-54e61c158876
	github.com/gardener/external-dns-management v0.7.21
	github.com/go-acme/lego/v4 v4.1.3
	github.com/go-openapi/spec v0.19.4 // indirect
	github.com/miekg/dns v1.1.31
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.2
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.7.1
	golang.org/x/lint v0.0.0-20200302205851-738671d3881b
	k8s.io/api v0.20.6
	k8s.io/apimachinery v0.20.6
	k8s.io/client-go v0.20.6
	k8s.io/code-generator v0.20.6
	k8s.io/kube-openapi v0.0.0-20201113171705-d219536bb9fd
	sigs.k8s.io/kind v0.10.0
)

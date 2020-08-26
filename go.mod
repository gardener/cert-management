module github.com/gardener/cert-management

go 1.13

require (
	github.com/ahmetb/gen-crd-api-reference-docs v0.2.0
	github.com/emicklei/go-restful v2.11.1+incompatible // indirect
	github.com/gardener/controller-manager-library v0.2.1-0.20200826084112-e3fae4e04030
	github.com/gardener/external-dns-management v0.7.17-0.20200810112859-d9ceb5e2257d
	github.com/go-acme/lego/v3 v3.7.0
	github.com/go-openapi/spec v0.19.4 // indirect
	github.com/miekg/dns v1.1.27
	github.com/onsi/ginkgo v1.14.0
	github.com/onsi/gomega v1.10.1
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.1.0
	github.com/prometheus/common v0.7.0 // indirect
	github.com/prometheus/procfs v0.0.5 // indirect
	golang.org/x/lint v0.0.0-20200302205851-738671d3881b
	k8s.io/api v0.18.6
	k8s.io/apiextensions-apiserver v0.18.6
	k8s.io/apimachinery v0.18.6
	k8s.io/client-go v0.18.6
	k8s.io/code-generator v0.18.6
	k8s.io/kube-openapi v0.0.0-20200410145947-bcb3869e6f29
	sigs.k8s.io/kind v0.8.0
)

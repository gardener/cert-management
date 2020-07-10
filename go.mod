module github.com/gardener/cert-management

go 1.13

require (
	github.com/ahmetb/gen-crd-api-reference-docs v0.1.5
	github.com/emicklei/go-restful v2.11.1+incompatible // indirect
	github.com/gardener/controller-manager-library v0.1.1-0.20200709142337-f9a87426b56d
	github.com/gardener/external-dns-management v0.7.10
	github.com/go-acme/lego/v3 v3.7.0
	github.com/go-openapi/spec v0.19.4 // indirect
	github.com/miekg/dns v1.1.27
	github.com/onsi/ginkgo v1.10.1
	github.com/onsi/gomega v1.7.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.1.0
	github.com/prometheus/common v0.7.0 // indirect
	github.com/prometheus/procfs v0.0.5 // indirect
	golang.org/x/lint v0.0.0-20200302205851-738671d3881b
	k8s.io/api v0.16.8
	k8s.io/apiextensions-apiserver v0.16.8
	k8s.io/apimachinery v0.17.0
	k8s.io/client-go v11.0.1-0.20190708175433-62e1c231c5dc+incompatible
	k8s.io/code-generator v0.16.8
	k8s.io/gengo v0.0.0-20191120174120-e74f70b9b27e // indirect
	k8s.io/kube-openapi v0.0.0-20191107075043-30be4d16710a
	sigs.k8s.io/kind v0.7.0
)

replace (
	k8s.io/api => k8s.io/api v0.16.8
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.16.8
	k8s.io/apimachinery => k8s.io/apimachinery v0.16.8
	k8s.io/client-go => k8s.io/client-go v0.16.8
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20191107075043-30be4d16710a
)

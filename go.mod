module github.com/gardener/cert-management

go 1.13

require (
	github.com/Masterminds/semver v1.4.2 // indirect
	github.com/ahmetb/gen-crd-api-reference-docs v0.1.5
	github.com/emicklei/go-restful v2.11.1+incompatible // indirect
	github.com/gardener/controller-manager-library v0.1.1-0.20191220121917-d7bc378737f9
	github.com/gardener/external-dns-management v0.7.3
	github.com/go-acme/lego/v3 v3.3.0
	github.com/go-openapi/spec v0.19.4 // indirect
	github.com/golang/groupcache v0.0.0-20190129154638-5b532d6fd5ef // indirect
	github.com/googleapis/gnostic v0.2.0 // indirect
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/onsi/ginkgo v1.10.1
	github.com/onsi/gomega v1.7.0
	github.com/prometheus/client_golang v1.1.0
	github.com/prometheus/client_model v0.0.0-20190812154241-14fe0d1b01d4 // indirect
	github.com/prometheus/common v0.7.0 // indirect
	github.com/prometheus/procfs v0.0.5 // indirect
	golang.org/x/lint v0.0.0-20191125180803-fdd1cda4f05f
	golang.org/x/oauth2 v0.0.0-20191122200657-5d9234df094c // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/api v0.16.4
	k8s.io/apiextensions-apiserver v0.0.0-20190502093314-7526e4c489ad
	k8s.io/apimachinery v0.16.4
	k8s.io/client-go v11.0.1-0.20190708175433-62e1c231c5dc+incompatible
	k8s.io/code-generator v0.16.4
	k8s.io/gengo v0.0.0-20191120174120-e74f70b9b27e // indirect
	k8s.io/klog v1.0.0 // indirect
	k8s.io/kube-openapi v0.0.0-20190816220812-743ec37842bf
	sigs.k8s.io/kind v0.6.1
)

replace (
	gopkg.in/fsnotify.v1 v1.4.7 => github.com/fsnotify/fsnotify v1.4.7
	k8s.io/api => k8s.io/api v0.16.4 // kubernetes-1.16.4
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.16.4 // kubernetes-1.16.4
	k8s.io/apimachinery => k8s.io/apimachinery v0.16.5-beta.1 // kubernetes-1.16.4
	k8s.io/client-go => k8s.io/client-go v0.16.4
	k8s.io/code-generator => k8s.io/code-generator v0.16.5-beta.1 // kubernetes-1.16.4
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20191107075043-30be4d16710a
)

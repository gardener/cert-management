module github.com/gardener/cert-management

go 1.13

require (
	github.com/Masterminds/semver v1.4.2 // indirect
	github.com/ahmetb/gen-crd-api-reference-docs v0.1.5
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/emicklei/go-restful v2.11.1+incompatible // indirect
	github.com/evanphx/json-patch v4.5.0+incompatible // indirect
	github.com/gardener/controller-manager-library v0.0.0-20190923111146-aa84113701ed
	github.com/gardener/external-dns-management v0.0.0-20190827161506-5a1241440366
	github.com/go-acme/lego v2.5.0+incompatible
	github.com/go-openapi/spec v0.19.4 // indirect
	github.com/gogo/protobuf v1.2.1 // indirect
	github.com/golang/groupcache v0.0.0-20190129154638-5b532d6fd5ef // indirect
	github.com/google/gofuzz v1.0.0 // indirect
	github.com/googleapis/gnostic v0.2.0 // indirect
	github.com/hashicorp/golang-lru v0.5.1 // indirect
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/konsorten/go-windows-terminal-sequences v1.0.2 // indirect
	github.com/miekg/dns v1.1.12 // indirect
	github.com/onsi/ginkgo v1.10.1
	github.com/onsi/gomega v1.7.0
	github.com/prometheus/client_golang v1.0.0
	github.com/prometheus/client_model v0.0.0-20190812154241-14fe0d1b01d4 // indirect
	github.com/prometheus/common v0.7.0 // indirect
	github.com/prometheus/procfs v0.0.5 // indirect
	github.com/spf13/cobra v0.0.3 // indirect
	golang.org/x/lint v0.0.0-20191125180803-fdd1cda4f05f
	golang.org/x/oauth2 v0.0.0-20191122200657-5d9234df094c // indirect
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/square/go-jose.v2 v2.3.1 // indirect
	k8s.io/api v0.0.0-20190708174958-539a33f6e817
	k8s.io/apiextensions-apiserver v0.0.0-20190502093314-7526e4c489ad
	k8s.io/apimachinery v0.0.0-20190502092502-a44ef629a3c9
	k8s.io/client-go v11.0.1-0.20190708175433-62e1c231c5dc+incompatible
	k8s.io/code-generator v0.0.0-20190713022532-93d7507fc8ff
	k8s.io/gengo v0.0.0-20191120174120-e74f70b9b27e // indirect
	k8s.io/klog v1.0.0 // indirect
	k8s.io/kube-openapi v0.0.0-20190430213458-20ad7abe0e6a
	k8s.io/utils v0.0.0-20190308190857-21c4ce38f2a7 // indirect
	sigs.k8s.io/yaml v1.1.0 // indirect
)

replace (
	gopkg.in/fsnotify.v1 v1.4.7 => github.com/fsnotify/fsnotify v1.4.7
	k8s.io/api => k8s.io/api v0.0.0-20191004102349-159aefb8556b // kubernetes-1.14.8
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.0.0-20190315093550-53c4693659ed // kubernetes-1.14.8
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20191004074956-c5d2f014d689 // kubernetes-1.14.8
	k8s.io/client-go => k8s.io/client-go v11.0.0+incompatible // kubernetes-1.14.0
	k8s.io/code-generator => k8s.io/code-generator v0.0.0-20190704094409-6c2a4329ac29 // kubernetes-1.14.8
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20190320154901-5e45bb682580
)

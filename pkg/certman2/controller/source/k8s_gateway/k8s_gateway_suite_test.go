package k8s_gateway

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestLandscape(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Kubernetes Gateway Source Controller Suite")
}

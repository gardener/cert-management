package issuer_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestLandscape(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Controller Issuer Suite")
}

package selfSigned_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSelfSigned(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SelfSigned Suite")
}

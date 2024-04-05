package deployer_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCertManagement(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Deployer Test Suite")
}

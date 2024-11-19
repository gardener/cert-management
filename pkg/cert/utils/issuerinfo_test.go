package utils_test

import (
	"github.com/gardener/cert-management/pkg/cert/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("IssuerInfo", func() {
	Context("#NewSelfSignedIssuerInfo", func() {
		It("should return a new self-signed issuer info", func() {
			issuerKey := utils.NewIssuerKey(utils.ClusterDefault, "test-namespace", "test-name")
			issuerInfo := utils.NewSelfSignedIssuerInfo(issuerKey)
			Expect(issuerInfo.Key()).To(Equal(issuerKey))
			Expect(issuerInfo.IssuerType()).To(Equal("selfSigned"))
		})
	})
})

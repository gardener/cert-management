// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package utils_test

import (
	"github.com/gardener/cert-management/pkg/cert/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("IssuerKey", func() {
	Describe("NewIssuerKey", func() {
		It("should return IssuerKey with empty namespace for DefaultCluster", func() {
			issuerKey := utils.NewIssuerKey(utils.ClusterDefault, "someNamespace", "Issuer Key Name")
			Expect(issuerKey.Namespace()).To(Equal(""))
			Expect(issuerKey.Name()).To(Equal("Issuer Key Name"))
		})

		It("should return IssuerKey with given namespace for non DefaultCluster", func() {
			issuerKey := utils.NewIssuerKey(1, "someNamespace", "Issuer Key Name")
			Expect(issuerKey.Namespace()).To(Equal("someNamespace"))
			Expect(issuerKey.Name()).To(Equal("Issuer Key Name"))
		})
	})

	Describe("NewDefaultClusterIssuerKey", func() {
		It("should return a new IssuerKey with empty namespace", func() {
			issuerKey := utils.NewDefaultClusterIssuerKey("Issuer Key Name")
			Expect(issuerKey.Namespace()).To(Equal(""))
			Expect(issuerKey.Name()).To(Equal("Issuer Key Name"))
		})
	})

	Describe("IssuerKey Methods", func() {
		var (
			defaultClusterIssuerKey utils.IssuerKey
			targetClusterIssuerKey  utils.IssuerKey
			randomClusterIssuerKey  utils.IssuerKey
		)

		BeforeEach(func() {
			defaultClusterIssuerKey = utils.NewDefaultClusterIssuerKey("default cluster issuer key")
			targetClusterIssuerKey = utils.NewIssuerKey(utils.ClusterTarget, "target namespace", "issuer key")
			randomClusterIssuerKey = utils.NewIssuerKey(3, "random namespace", "issuer key")
		})

		Describe("NamespaceOrDefault", func() {
			It("should return the given default for default cluster", func() {
				Expect(defaultClusterIssuerKey.NamespaceOrDefault("some default")).To(Equal("some default"))
			})

			It("should return the namespace for non default cluster", func() {
				Expect(targetClusterIssuerKey.NamespaceOrDefault("some default")).To(Equal(targetClusterIssuerKey.Namespace()))
				Expect(randomClusterIssuerKey.NamespaceOrDefault("some default")).To(Equal(randomClusterIssuerKey.Namespace()))
			})
		})

		Describe("Secondary", func() {
			It("should be true for default cluster", func() {
				Expect(defaultClusterIssuerKey.Secondary()).To(BeTrue())
			})
			
			It("should be false for non default cluster", func() {
				Expect(targetClusterIssuerKey.Secondary()).To(BeFalse())
				Expect(randomClusterIssuerKey.Secondary()).To(BeFalse())
			})
		})

		Describe("ClusterName", func() {
			It("should return 'default' for default cluster", func() {
				Expect(defaultClusterIssuerKey.ClusterName()).To(Equal("default"))
			})
			
			It("should return 'target' for target cluster", func() {
				Expect(targetClusterIssuerKey.ClusterName()).To(Equal("target"))
			})
			
			It("should return '' for other clusters", func() {
				Expect(randomClusterIssuerKey.ClusterName()).To(Equal(""))
			})
		})
	})
})

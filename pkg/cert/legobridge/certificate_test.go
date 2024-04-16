/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package legobridge

import (
	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"

	"github.com/go-acme/lego/v4/certcrypto"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/utils/ptr"
)

var _ = DescribeTable("KeyType conversion",
	func(keyType certcrypto.KeyType, algorithm api.PrivateKeyAlgorithm, size int) {
		defaults, err := NewCertificatePrivateKeyDefaults(api.RSAKeyAlgorithm, 2048, 256)
		Expect(err).ToNot(HaveOccurred())

		var key *api.CertificatePrivateKey
		if len(algorithm) > 0 {
			key = &api.CertificatePrivateKey{Algorithm: ptr.To(algorithm)}
		}
		if size > 0 {
			if key == nil {
				key = &api.CertificatePrivateKey{}
			}
			key.Size = ptr.To(api.PrivateKeySize(size))
		}
		actualKeyType, err := defaults.ToKeyType(key)
		if keyType == "" {
			Expect(err).To(HaveOccurred())
		} else {
			Expect(err).ToNot(HaveOccurred())
			Expect(actualKeyType).To(Equal(keyType))
			actualKeyType, err = defaults.ToKeyType(FromKeyType(keyType))
			Expect(err).ToNot(HaveOccurred())
			Expect(actualKeyType).To(Equal(keyType))
		}
	},
	Entry("default", certcrypto.RSA2048, api.PrivateKeyAlgorithm(""), 0),
	Entry("RSA from empty config", certcrypto.RSA2048, api.RSAKeyAlgorithm, 0),
	Entry("RSA2048", certcrypto.RSA2048, api.RSAKeyAlgorithm, 2048),
	Entry("RSA3072", certcrypto.RSA3072, api.RSAKeyAlgorithm, 3072),
	Entry("RSA4096", certcrypto.RSA4096, api.RSAKeyAlgorithm, 4096),
	Entry("ECDSA with default size", certcrypto.EC256, api.ECDSAKeyAlgorithm, 0),
	Entry("EC256", certcrypto.EC256, api.ECDSAKeyAlgorithm, 256),
	Entry("EC384", certcrypto.EC384, api.ECDSAKeyAlgorithm, 384),
	Entry("RSA with wrong size", certcrypto.KeyType(""), api.RSAKeyAlgorithm, 8192),
	Entry("ECDSA with wrong size", certcrypto.KeyType(""), api.ECDSAKeyAlgorithm, 511),
)

/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package legobridge

import (
	"github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/go-acme/lego/v4/certcrypto"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("KeyType conversion",
	func(keyType certcrypto.KeyType, key *v1alpha1.CertificatePrivateKey) {
		actualKeyType, err := ToKeyType(key)
		if keyType == "" {
			Expect(err).To(HaveOccurred())
		} else {
			Expect(err).ToNot(HaveOccurred())
			Expect(actualKeyType).To(Equal(keyType))
			actualKeyType, err = ToKeyType(FromKeyType(keyType))
			Expect(err).ToNot(HaveOccurred())
			Expect(actualKeyType).To(Equal(keyType))
		}
	},
	Entry("default", certcrypto.RSA2048, nil),
	Entry("RSA with default size", certcrypto.RSA2048, &v1alpha1.CertificatePrivateKey{Algorithm: v1alpha1.RSAKeyAlgorithm}),
	Entry("RSA2048", certcrypto.RSA2048, &v1alpha1.CertificatePrivateKey{Algorithm: v1alpha1.RSAKeyAlgorithm, Size: 2048}),
	Entry("RSA3072", certcrypto.RSA3072, &v1alpha1.CertificatePrivateKey{Algorithm: v1alpha1.RSAKeyAlgorithm, Size: 3072}),
	Entry("RSA4096", certcrypto.RSA4096, &v1alpha1.CertificatePrivateKey{Algorithm: v1alpha1.RSAKeyAlgorithm, Size: 4096}),
	Entry("ECDSA with default size", certcrypto.EC256, &v1alpha1.CertificatePrivateKey{Algorithm: v1alpha1.ECDSAKeyAlgorithm}),
	Entry("EC256", certcrypto.EC256, &v1alpha1.CertificatePrivateKey{Algorithm: v1alpha1.ECDSAKeyAlgorithm, Size: 256}),
	Entry("EC384", certcrypto.EC384, &v1alpha1.CertificatePrivateKey{Algorithm: v1alpha1.ECDSAKeyAlgorithm, Size: 384}),
	Entry("RSA with wrong size", certcrypto.KeyType(""), &v1alpha1.CertificatePrivateKey{Algorithm: v1alpha1.RSAKeyAlgorithm, Size: 8192}),
	Entry("ECDSA with wrong size", certcrypto.KeyType(""), &v1alpha1.CertificatePrivateKey{Algorithm: v1alpha1.ECDSAKeyAlgorithm, Size: 511}),
)

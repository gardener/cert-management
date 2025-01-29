// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package legobridge_test

import (
	"github.com/gardener/cert-management/pkg/cert/legobridge"
	corev1 "k8s.io/api/core/v1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Pending", func() {
	Describe("RemoveKeystoresFromSecret", func() {
		It("should do nothing if secret is nil", func() {
			Expect(func() {
				legobridge.RemoveKeystoresFromSecret(nil)
			}).NotTo(Panic())
		})

		It("should do nothing if the data in the secret is nil", func() {
			secret := &corev1.Secret{}
			legobridge.RemoveKeystoresFromSecret(secret)
			Expect(secret.Data).To(BeNil())
		})

		It("should remove the keystore data from the secret", func() {
			secret := &corev1.Secret{
				Data: map[string][]byte{
					"Field1":                   []byte("Field1"),
					"Field2":                   []byte("Field2"),
					legobridge.PKCS12SecretKey: []byte(legobridge.PKCS12SecretKey),
				},
			}
			legobridge.RemoveKeystoresFromSecret(secret)
			Expect(secret.Data).To(Equal(map[string][]byte{
				"Field1": []byte("Field1"),
				"Field2": []byte("Field2"),
			}))
		})
	})
})

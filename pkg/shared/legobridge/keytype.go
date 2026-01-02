// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package legobridge

// Constants for all key types we support.
const (
	// EC256 ECDSA with size 256 bits
	EC256 = KeyType("P256")
	// EC384 ECDSA with size 384 bits
	EC384 = KeyType("P384")
	// RSA2048 RSA with size 2048 bits
	RSA2048 = KeyType("2048")
	// RSA3072 RSA with size 3072 bits
	RSA3072 = KeyType("3072")
	// RSA4096 RSA with size 4096 bits
	RSA4096 = KeyType("4096")

	// Note: RSA8192 is not supported because of performance reasons. Generating such keys takes too long (~30s), mainly because finding large primes takes much longer.
)

// KeyType represents the key algo as well as the key size or curve to use.
type KeyType string

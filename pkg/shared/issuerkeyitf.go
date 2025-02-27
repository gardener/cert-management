/*
 * SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package shared

// Cluster is an enum for default and target cluster
type Cluster int

const (
	// ClusterDefault is the default cluster (= secondary)
	ClusterDefault Cluster = iota
	// ClusterTarget is the target cluster (= primary)
	ClusterTarget
)

// IssuerKeyItf abstracts IssuerKey to simplify code reuse.
type IssuerKeyItf interface {
	Name() string
	Namespace() string
	Cluster() Cluster
	Secondary() bool
	String() string
}

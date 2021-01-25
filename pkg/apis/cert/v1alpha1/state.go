/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package v1alpha1

const (
	// StatePending is the pending state.
	StatePending = "Pending"
	// StateError is the error state.
	StateError = "Error"
	// StateReady is the ready state.
	StateReady = "Ready"
	// StateRevoked is the revoked state.
	StateRevoked = "Revoked"
	// StateRevocationApplied is the applied state.
	StateRevocationApplied = "Applied"
	// StateRevocationPartialApplied is the partial applied state (partial success).
	StateRevocationPartialApplied = "PartialApplied"
)

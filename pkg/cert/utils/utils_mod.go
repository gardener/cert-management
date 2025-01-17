/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package utils

import (
	"github.com/gardener/controller-manager-library/pkg/resources/abstract"
)

// AssureStringSlice handles modification of a string slice.
func AssureStringSlice(mod *abstract.ModificationState, dst *[]string, value []string) {
	if value == nil {
		value = []string{}
	}
	if !EqualStringSlice(*dst, value) {
		*dst = value
		mod.Modify(true)
	}
}

// EqualStringSlice compares string slices.
func EqualStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

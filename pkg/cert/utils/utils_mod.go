/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package utils

import (
	"github.com/gardener/controller-manager-library/pkg/resources/abstract"
)

// AssureStringArray handles modification of a string array.
func AssureStringArray(mod *abstract.ModificationState, dst *[]string, value []string) {
	if value == nil {
		value = []string{}
	}
	if !EqualStringArray(*dst, value) {
		*dst = value
		mod.Modify(true)
	}
}

// EqualStringArray compares string arrays.
func EqualStringArray(a, b []string) bool {
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

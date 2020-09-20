/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package utils

import (
	"testing"
)

func TestIsInDomainRange(t *testing.T) {
	table := []struct {
		domain      string
		domainRange string
		wanted      bool
	}{
		{"a.b", "b", true},
		{"A.B", "b", true},
		{"a.b", ".b", true},
		{"a.b", "*.B", true},
		{"a.b", "a.b", true},
		{"a.b", "c.b", false},
		{"a.b", "a.b.c", false},
		{"a.b.c", "b.c", true},
		{"a.xb.c", "b.c", false},
		{"a.b", "b.", true},
		{"a.b.", "b", true},
	}
	for _, entry := range table {
		domainRange := NormalizeDomainRange(entry.domainRange)
		result := IsInDomainRange(entry.domain, domainRange)
		if result != entry.wanted {
			t.Errorf("domain=%s, domainRange=%s: wanted %t", entry.domain, entry.domainRange, entry.wanted)
		}
	}
}

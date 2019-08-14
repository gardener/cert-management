/*
 * Copyright 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 *
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

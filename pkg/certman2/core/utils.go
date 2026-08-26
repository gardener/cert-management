/*
 * SPDX-FileCopyrightText: Copyright Contributors to the Gardener project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package core

import "strings"

// DomainsString creates a comma separated string.
func DomainsString(domains []string) string {
	if domains == nil {
		return ""
	}
	return strings.Join(domains, ",")
}

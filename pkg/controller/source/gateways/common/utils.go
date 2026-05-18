// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package common

import "strings"

// MatchesWildcardSingleSubdomain checks whether 'h' is a wildcard pattern (*.X) that matches 'host'
// as a single-level subdomain. It returns true only if 'h' starts with "*.", and 'host' has exactly
// one additional label prepended to the base domain of 'h'.
// Examples:
//   - host: foo.gardener.cloud,   h: *.gardener.cloud     -> true
//   - host: gardener.cloud,       h: *.gardener.cloud     -> false (host is the base domain itself)
//   - host: a.b.gardener.cloud,   h: *.gardener.cloud     -> false (multi-level subdomain)
//   - host: foo.gardener.cloud,   h: docs.gardener.cloud  -> false (h is not a wildcard)
//   - host: example.com,          h: *.gardener.cloud     -> false (unrelated domain)
func MatchesWildcardSingleSubdomain(host, h string) bool {
	return strings.HasPrefix(h, "*.") && strings.HasSuffix(host, h[1:]) && !strings.Contains(host[:len(host)-len(h)+1], ".")
}

// MatchesWildcardAnySubdomain checks whether 'h' is a wildcard pattern (*.X) that matches 'host' with any level of subdomains.
func MatchesWildcardAnySubdomain(host, h string) bool {
	return strings.HasPrefix(h, "*.") && strings.HasSuffix(host, h[1:])
}

// IsWildcard reports whether `host` is a wildcard host pattern (for example, `*.example.com`).
func IsWildcard(host string) bool {
	return strings.HasPrefix(host, "*.")
}

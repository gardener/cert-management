/*
 * SPDX-FileCopyrightText: Contributors to the Gardener project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package utils

import "strings"

// NormalizeDomainRange normalizes domain to lower case, drops wildcard and suffix dot.
func NormalizeDomainRange(domainRange string) string {
	normalized := strings.ToLower(domainRange)
	if strings.HasPrefix(normalized, "*.") {
		normalized = normalized[1:]
	}
	normalized = strings.TrimSuffix(normalized, ".")
	return normalized
}

// IsInDomainRanges returns true if domain is in domain ranges.
func IsInDomainRanges(domain string, domainRanges []string) bool {
	if domainRanges == nil {
		return true
	}
	for _, domainRange := range domainRanges {
		if IsInDomainRange(domain, domainRange) {
			return true
		}
	}
	return false
}

// BestDomainRange returns best fitting domain range value or "".
func BestDomainRange(domain string, domainRanges []string) string {
	if domainRanges == nil {
		return "*"
	}
	best := ""
	for _, domainRange := range domainRanges {
		if IsInDomainRange(domain, domainRange) {
			if len(best) < len(domainRange) {
				best = domainRange
			}
		}
	}
	return best
}

// IsInDomainRange returns true if domain is in domain range.
// A wildcard domain (e.g. *.example.com) also matches a range below its zone
// (e.g. secret.example.com), since the issued certificate covers that name.
func IsInDomainRange(domain, domainRange string) bool {
	wildcard := strings.HasPrefix(strings.ToLower(domain), "*.")
	domainRange = NormalizeDomainRange(domainRange)
	if domainRange == "" {
		return true
	}
	domain = NormalizeDomainRange(domain)
	// wildcard *.example.com covers single-label children, so a range like
	// secret.example.com (one label below the zone) is within its coverage.
	// domain is ".example.com" here, so rest is the single child label.
	if wildcard && strings.HasSuffix(domainRange, domain) {
		rest := domainRange[:len(domainRange)-len(domain)]
		if rest != "" && !strings.Contains(rest, ".") {
			return true
		}
	}
	if !strings.HasSuffix(domain, domainRange) {
		return false
	}
	if len(domain) == len(domainRange) {
		return true
	}

	return domainRange[0] == '.' || domain[len(domain)-len(domainRange)-1] == '.'
}

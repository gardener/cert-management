/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
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
func IsInDomainRange(domain, domainRange string) bool {
	if domainRange == "" {
		return true
	}
	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")
	if !strings.HasSuffix(domain, domainRange) {
		return false
	}
	if len(domain) == len(domainRange) {
		return true
	}

	return domainRange[0] == '.' || domain[len(domain)-len(domainRange)-1] == '.'
}

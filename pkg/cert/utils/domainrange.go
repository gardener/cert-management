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

import "strings"

func NormalizeDomainRange(domainRange string) string {
	normalized := strings.ToLower(domainRange)
	if strings.HasPrefix(normalized, "*.") {
		normalized = normalized[1:]
	}
	if strings.HasSuffix(normalized, ".") {
		normalized = normalized[0 : len(normalized)-1]
	}
	return normalized
}

func IsInDomainRange(domain, domainRange string) bool {
	if domainRange == "" {
		return true
	}
	domain = strings.ToLower(domain)
	if strings.HasSuffix(domain, ".") {
		domain = domain[0 : len(domain)-1]
	}
	if !strings.HasSuffix(domain, domainRange) {
		return false
	}
	if len(domain) == len(domainRange) {
		return true
	}

	return domainRange[0] == '.' || domain[len(domain)-len(domainRange)-1] == '.'
}

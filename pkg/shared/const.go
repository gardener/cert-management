/*
 * SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package shared

const (
	// AnnotDNSClass is the annotation for the dns class
	AnnotDNSClass = "dns.gardener.cloud/class"
	// AnnotACMEDNSChallenge is the annotation for marking DNSEntries for DNS challenges
	AnnotACMEDNSChallenge = "cert.gardener.cloud/acme-dns-challenge"
)

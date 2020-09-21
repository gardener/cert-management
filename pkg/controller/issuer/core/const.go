/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package core

const (
	// OptDefaultIssuer is the default-issuer command line option.
	OptDefaultIssuer = "default-issuer"
	// OptIssuerNamespace is the issuer namespace command line option.
	OptIssuerNamespace = "issuer-namespace"
	// OptDNSNamespace is the DNS namespace command line option.
	OptDNSNamespace = "dns-namespace"
	// OptDNSClass is the DNS class command line option.
	OptDNSClass = "dns-class"
	// OptDNSOwnerID is the DNS owner identifier command line option.
	OptDNSOwnerID = "dns-owner-id"
	// OptDefaultIssuerDomainRanges are the domain ranges the default issuer is restricted to.
	OptDefaultIssuerDomainRanges = "default-issuer-domain-ranges"
	// OptRenewalWindow is the renewal window command line option.
	OptRenewalWindow = "renewal-window"
	// OptCascadeDelete is the cascade delete command line option.
	OptCascadeDelete = "cascade-delete"
	// OptPrecheckNameservers is a command line option to specify the DNS nameservers to check DNS propagation of the DNS challenge.
	OptPrecheckNameservers = "precheck-nameservers"
	// OptPrecheckAdditionalWait is a command line option to specify an additional wait time after DNS propagation check.
	OptPrecheckAdditionalWait = "precheck-additional-wait"
	// OptDefaultRequestsPerDayQuota allows to set a default value for requestsPerDayQuota if not set explicitly in the issuer spec.
	OptDefaultRequestsPerDayQuota = "default-requests-per-day-quota"
	// OptPropagationTimeout is the propagation timeout for the DNS01 challenge.
	OptPropagationTimeout = "propagation-timeout"
)

/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package core

const (
	// ACMEType is the type name for ACME.
	ACMEType = "acme"
	// CAType is the type name for CA.
	CAType = "ca"
)

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
	// OptRenewalOverdueWindow is the renewal overdue window command line option.
	OptRenewalOverdueWindow = "renewal-overdue-window"
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
	// OptAllowTargetIssuers if true reconciles not only issuers on the default cluster, but also on the target cluster
	OptAllowTargetIssuers = "allow-target-issuers"
)

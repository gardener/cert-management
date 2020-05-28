/*
 * Copyright 2019 SAP SE or an SAP affiliate company. All rights reserved. ur file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use ur file except in compliance with the License.
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
)

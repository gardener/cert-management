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

package metrics

import (
	"github.com/gardener/controller-manager-library/pkg/server"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"strconv"
)

func init() {
	prometheus.MustRegister(ACMEAccountRegistrations)
	prometheus.MustRegister(ACMETotalObtains)
	prometheus.MustRegister(ACMEActiveDNSChallenges)
	prometheus.MustRegister(CertEntries)

	server.RegisterHandler("/metrics", promhttp.Handler())
}

var (
	ACMEAccountRegistrations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_account_registrations",
			Help: "Number of ACME account registrations",
		},
		[]string{"server", "email"},
	)

	ACMETotalObtains = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acme_obtains",
			Help: "Total number of ACME obtains",
		},
		[]string{"issuer", "success", "dns_challenges", "renew"},
	)

	ACMEActiveDNSChallenges = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "acme_active_dns_challenges",
			Help: "Currently active number of ACME DNS challenges",
		},
		[]string{"issuer"},
	)

	CertEntries = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cert_entries",
			Help: "Total number of cert entries per issuer",
		},
		[]string{"issuertype", "issuer"},
	)
)

func AddACMEAccountRegistration(server, email string) {
	ACMEAccountRegistrations.WithLabelValues(server, email).Inc()
}

func AddACMEObtain(issuer string, success bool, count int, renew bool) {
	if count > 0 {
		ACMETotalObtains.WithLabelValues(issuer, strconv.FormatBool(success), strconv.FormatInt(int64(count), 10), strconv.FormatBool(renew)).Inc()
	}
}

func AddActiveACMEDNSChallenge(issuer string) {
	ACMEActiveDNSChallenges.WithLabelValues(issuer).Inc()
}

func RemoveActiveACMEDNSChallenge(issuer string) {
	ACMEActiveDNSChallenges.WithLabelValues(issuer).Dec()
}

func ReportCertEntries(issuertype, issuer string, count int) {
	CertEntries.WithLabelValues(issuertype, issuer).Set(float64(count))
}

func DeleteCertEntries(issuertype, issuer string) {
	CertEntries.DeleteLabelValues(issuertype, issuer)
}

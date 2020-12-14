/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
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
	// ACMEAccountRegistrations is the acme_account_registrations counter.
	ACMEAccountRegistrations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cert_management_acme_account_registrations",
			Help: "Number of ACME account registrations",
		},
		[]string{"server", "email"},
	)

	// ACMETotalObtains is the acme_obtains counter.
	ACMETotalObtains = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cert_management_acme_obtains",
			Help: "Total number of ACME obtains",
		},
		[]string{"issuer", "success", "dns_challenges", "renew"},
	)

	// ACMEActiveDNSChallenges is the acme_active_dns_challenges gauge.
	ACMEActiveDNSChallenges = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cert_management_acme_active_dns_challenges",
			Help: "Currently active number of ACME DNS challenges",
		},
		[]string{"issuer"},
	)

	// CertEntries is the cert_entries gauge.
	CertEntries = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cert_management_cert_entries",
			Help: "Total number of certificate objects per issuer",
		},
		[]string{"issuertype", "issuer"},
	)
)

// AddACMEAccountRegistration increments the ACMEAccountRegistrations counter.
func AddACMEAccountRegistration(server, email string) {
	ACMEAccountRegistrations.WithLabelValues(server, email).Inc()
}

// AddACMEObtain increments the ACMETotalObtains counter.
func AddACMEObtain(issuer string, success bool, count int, renew bool) {
	if count > 0 {
		ACMETotalObtains.WithLabelValues(issuer, strconv.FormatBool(success), strconv.FormatInt(int64(count), 10), strconv.FormatBool(renew)).Inc()
	}
}

// AddActiveACMEDNSChallenge increments the ACMEActiveDNSChallenges gauge.
func AddActiveACMEDNSChallenge(issuer string) {
	ACMEActiveDNSChallenges.WithLabelValues(issuer).Inc()
}

// RemoveActiveACMEDNSChallenge decrements the ACMEActiveDNSChallenges gauge.
func RemoveActiveACMEDNSChallenge(issuer string) {
	ACMEActiveDNSChallenges.WithLabelValues(issuer).Dec()
}

// ReportCertEntries sets the CertEntries gauge
func ReportCertEntries(issuertype, issuer string, count int) {
	CertEntries.WithLabelValues(issuertype, issuer).Set(float64(count))
}

// DeleteCertEntries deletes a CertEntries gauge entry.
func DeleteCertEntries(issuertype, issuer string) {
	CertEntries.DeleteLabelValues(issuertype, issuer)
}

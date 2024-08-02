/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package core

import (
	"sync"

	"k8s.io/client-go/util/flowcontrol"
)

// NewQuotas create a Quotas
func NewQuotas() *Quotas {
	return &Quotas{
		issuerToQuotas: map[IssuerKey]quotas{},
	}
}

type quotas struct {
	rateLimiter    flowcontrol.RateLimiter
	requestsPerDay int
}

// Quotas stores references issuer quotas.
type Quotas struct {
	lock           sync.Mutex
	issuerToQuotas map[IssuerKey]quotas
}

// RememberQuotas stores the requests per days quota and creates a new ratelimiter if the quota changed.
func (q *Quotas) RememberQuotas(issuerKey IssuerKey, requestsPerDay int) {
	q.lock.Lock()
	defer q.lock.Unlock()

	if quotas, ok := q.issuerToQuotas[issuerKey]; ok {
		if quotas.requestsPerDay == requestsPerDay {
			return
		}
	}

	qps := float32(requestsPerDay) / 86400
	burst := requestsPerDay / 4
	if burst < 1 {
		burst = 1
	}

	q.issuerToQuotas[issuerKey] = quotas{
		rateLimiter:    flowcontrol.NewTokenBucketRateLimiter(qps, burst),
		requestsPerDay: requestsPerDay,
	}
}

// TryAccept tries to accept a certificate request according to the quotas.
// Returns true if accepted and the requests per days quota value
func (q *Quotas) TryAccept(issuerKey IssuerKey) (bool, int) {
	q.lock.Lock()
	defer q.lock.Unlock()

	if quotas, ok := q.issuerToQuotas[issuerKey]; ok {
		return quotas.rateLimiter.TryAccept(), quotas.requestsPerDay
	}
	return false, 0
}

// RemoveIssuer removes all secretRefs for an issuer.
func (q *Quotas) RemoveIssuer(issuerKey IssuerKey) {
	q.lock.Lock()
	defer q.lock.Unlock()

	delete(q.issuerToQuotas, issuerKey)
}

// RequestsPerDay gets the request per day quota
func (q *Quotas) RequestsPerDay(issuerName IssuerKey) int {
	q.lock.Lock()
	defer q.lock.Unlock()

	quotas, ok := q.issuerToQuotas[issuerName]
	if !ok {
		return 0
	}
	return quotas.requestsPerDay
}

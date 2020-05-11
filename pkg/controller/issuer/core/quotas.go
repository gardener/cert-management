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

import (
	"sync"

	"github.com/gardener/controller-manager-library/pkg/resources"
	"k8s.io/client-go/util/flowcontrol"
)

// NewQuotas create a Quotas
func NewQuotas() *Quotas {
	return &Quotas{
		issuerToQuotas: map[resources.ObjectName]quotas{},
	}
}

type quotas struct {
	rateLimiter    flowcontrol.RateLimiter
	requestsPerDay int
}

// Quotas stores references issuer quotas.
type Quotas struct {
	lock           sync.Mutex
	issuerToQuotas map[resources.ObjectName]quotas
}

// RememberQuotas stores the requests per days quota and creates a new ratelimiter if the quota changed.
func (q *Quotas) RememberQuotas(issuerName resources.ObjectName, requestsPerDay int) {
	q.lock.Lock()
	defer q.lock.Unlock()

	if quotas, ok := q.issuerToQuotas[issuerName]; ok {
		if quotas.requestsPerDay == requestsPerDay {
			return
		}
	}

	qps := float32(requestsPerDay) / 86400
	burst := requestsPerDay / 4
	if burst < 1 {
		burst = 1
	}

	q.issuerToQuotas[issuerName] = quotas{
		rateLimiter:    flowcontrol.NewTokenBucketRateLimiter(qps, burst),
		requestsPerDay: requestsPerDay,
	}
}

// TryAccept tries to accept a certificate request according to the quotas.
// Returns true if accepted and the requests per days quota value
func (q *Quotas) TryAccept(issuerName resources.ObjectName) (bool, int) {
	q.lock.Lock()
	defer q.lock.Unlock()

	if quotas, ok := q.issuerToQuotas[issuerName]; ok {
		return quotas.rateLimiter.TryAccept(), quotas.requestsPerDay
	}
	return false, 0
}

// RemoveIssuer removes all secretRefs for an issuer.
func (q *Quotas) RemoveIssuer(issuerName resources.ObjectName) {
	q.lock.Lock()
	defer q.lock.Unlock()

	delete(q.issuerToQuotas, issuerName)
}

// RequestsPerDay gets the request per day quota
func (q *Quotas) RequestsPerDay(issuerName resources.ObjectName) int {
	q.lock.Lock()
	defer q.lock.Unlock()

	quotas, ok := q.issuerToQuotas[issuerName]
	if !ok {
		return 0
	}
	return quotas.requestsPerDay
}

/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package legobridge

import (
	"sync"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// PendingCertificateRequests contains the pending certificate requests.
type PendingCertificateRequests struct {
	lock     sync.Mutex
	requests map[client.ObjectKey]time.Time
}

// NewPendingRequests creates a new PendingCertificateRequests
func NewPendingRequests() *PendingCertificateRequests {
	return &PendingCertificateRequests{requests: map[client.ObjectKey]time.Time{}}
}

// Add adds a certificate object name.
func (pr *PendingCertificateRequests) Add(name client.ObjectKey) {
	pr.lock.Lock()
	defer pr.lock.Unlock()

	pr.requests[name] = time.Now()
}

// Contains check if a certificate object name is pending.
func (pr *PendingCertificateRequests) Contains(name client.ObjectKey) bool {
	pr.lock.Lock()
	defer pr.lock.Unlock()

	t, ok := pr.requests[name]
	return ok && !t.Add(5*time.Minute).Before(time.Now())
}

// Remove removes a certificate object name from the pending list.
func (pr *PendingCertificateRequests) Remove(name client.ObjectKey) {
	pr.lock.Lock()
	defer pr.lock.Unlock()

	delete(pr.requests, name)
}

// PendingResults caches the ObtainOutput results.
type PendingResults struct {
	lock    sync.Mutex
	results map[client.ObjectKey]*ObtainOutput
}

// NewPendingResults creates a new PendingResults.
func NewPendingResults() *PendingResults {
	return &PendingResults{results: map[client.ObjectKey]*ObtainOutput{}}
}

// Add adds a object name / ObtainOutput pair.
func (pr *PendingResults) Add(name client.ObjectKey, result *ObtainOutput) {
	pr.lock.Lock()
	defer pr.lock.Unlock()

	pr.results[name] = result
}

// Peek fetches a pending result by object name.
func (pr *PendingResults) Peek(name client.ObjectKey) *ObtainOutput {
	pr.lock.Lock()
	defer pr.lock.Unlock()

	return pr.results[name]
}

// Remove removes a pending result by object name.
func (pr *PendingResults) Remove(name client.ObjectKey) {
	pr.lock.Lock()
	defer pr.lock.Unlock()

	delete(pr.results, name)
}

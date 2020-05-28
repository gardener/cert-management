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

package legobridge

import (
	"sync"
	"time"

	"github.com/gardener/controller-manager-library/pkg/resources"
)

// PendingCertificateRequests contains the pending certificate requests.
type PendingCertificateRequests struct {
	lock     sync.Mutex
	requests map[resources.ObjectName]time.Time
}

// NewPendingRequests creates a new PendingCertificateRequests
func NewPendingRequests() *PendingCertificateRequests {
	return &PendingCertificateRequests{requests: map[resources.ObjectName]time.Time{}}
}

// Add adds a certificate object name.
func (pr *PendingCertificateRequests) Add(name resources.ObjectName) {
	pr.lock.Lock()
	defer pr.lock.Unlock()

	pr.requests[name] = time.Now()
}

// Contains check if a certificate object name is pending.
func (pr *PendingCertificateRequests) Contains(name resources.ObjectName) bool {
	pr.lock.Lock()
	defer pr.lock.Unlock()

	t, ok := pr.requests[name]
	return ok && !t.Add(5*time.Minute).Before(time.Now())
}

// Remove removes a certificate object name from the pending list.
func (pr *PendingCertificateRequests) Remove(name resources.ObjectName) {
	pr.lock.Lock()
	defer pr.lock.Unlock()

	delete(pr.requests, name)
}

// PendingResults caches the ObtainOutput results.
type PendingResults struct {
	lock    sync.Mutex
	results map[resources.ObjectName]*ObtainOutput
}

// NewPendingResults creates a new PendingResults.
func NewPendingResults() *PendingResults {
	return &PendingResults{results: map[resources.ObjectName]*ObtainOutput{}}
}

// Add adds a object name / ObtainOutput pair.
func (pr *PendingResults) Add(name resources.ObjectName, result *ObtainOutput) {
	pr.lock.Lock()
	defer pr.lock.Unlock()

	pr.results[name] = result
}

// Peek fetches a pending result by object name.
func (pr *PendingResults) Peek(name resources.ObjectName) *ObtainOutput {
	pr.lock.Lock()
	defer pr.lock.Unlock()

	return pr.results[name]
}

// Remove removes a pending result by object name.
func (pr *PendingResults) Remove(name resources.ObjectName) {
	pr.lock.Lock()
	defer pr.lock.Unlock()

	delete(pr.results, name)
}

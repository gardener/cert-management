/*
 * SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package core

import (
	"sync"

	"github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
)

// NewIssuerDNSSelections creates an IssuerDNSSelections
func NewIssuerDNSSelections() *IssuerDNSSelections {
	return &IssuerDNSSelections{
		selections: map[IssuerKey]*v1alpha1.DNSSelection{},
	}
}

// IssuerDNSSelections stores last known DNS selection for an issuer
type IssuerDNSSelections struct {
	lock       sync.Mutex
	selections map[IssuerKey]*v1alpha1.DNSSelection
}

// Add adds a DNS selection
func (s *IssuerDNSSelections) Add(key IssuerKey, sel *v1alpha1.DNSSelection) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.selections[key] = sel
}

// Remove removes a DNS selection
func (s *IssuerDNSSelections) Remove(key IssuerKey) {
	s.lock.Lock()
	defer s.lock.Unlock()

	delete(s.selections, key)
}

// GetSelection returns the selection for the given key.
func (s *IssuerDNSSelections) GetSelection(key IssuerKey) *v1alpha1.DNSSelection {
	s.lock.Lock()
	defer s.lock.Unlock()

	return s.selections[key]
}

// Issuers returns all issuer keys.
func (s *IssuerDNSSelections) Issuers() []IssuerKey {
	s.lock.Lock()
	defer s.lock.Unlock()

	keys := []IssuerKey{}
	for key := range s.selections {
		keys = append(keys, key)
	}
	return keys
}

// GetAll returns a map with all selections
func (s *IssuerDNSSelections) GetAll() map[IssuerKey]*v1alpha1.DNSSelection {
	s.lock.Lock()
	defer s.lock.Unlock()

	result := map[IssuerKey]*v1alpha1.DNSSelection{}
	for k, v := range s.selections {
		result[k] = v
	}
	return result
}

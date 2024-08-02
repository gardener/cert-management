/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package core

import (
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NewAssociatedObjects creates an AssociatedObjects
func NewAssociatedObjects() *AssociatedObjects {
	return &AssociatedObjects{
		issuerToCerts: map[IssuerKey]sets.Set[client.ObjectKey]{},
		certsToIssuer: map[client.ObjectKey]IssuerKey{},
	}
}

// AssociatedObjects stores bidi-associations between issuer and associated certificates.
type AssociatedObjects struct {
	lock          sync.Mutex
	issuerToCerts map[IssuerKey]sets.Set[client.ObjectKey]
	certsToIssuer map[client.ObjectKey]IssuerKey
}

// AddAssoc adds an association.
func (ao *AssociatedObjects) AddAssoc(issuer IssuerKey, cert client.ObjectKey) {
	ao.lock.Lock()
	defer ao.lock.Unlock()

	set := ao.issuerToCerts[issuer]
	if set == nil {
		set = sets.Set[client.ObjectKey]{}
		ao.issuerToCerts[issuer] = set
	}
	set.Insert(cert)
	ao.certsToIssuer[cert] = issuer
}

// RemoveByCertificate removes an association by dest.
func (ao *AssociatedObjects) RemoveByCertificate(cert client.ObjectKey) {
	ao.lock.Lock()
	defer ao.lock.Unlock()

	if issuer, ok := ao.certsToIssuer[cert]; ok {
		if set := ao.issuerToCerts[issuer]; set != nil {
			set.Delete(cert)
			if len(set) == 0 {
				delete(ao.issuerToCerts, issuer)
			}
		}
		delete(ao.certsToIssuer, cert)
	}
}

// RemoveByIssuer removes an association by issuer.
func (ao *AssociatedObjects) RemoveByIssuer(issuer IssuerKey) {
	ao.lock.Lock()
	defer ao.lock.Unlock()

	if set := ao.issuerToCerts[issuer]; set != nil {
		for cert := range set {
			delete(ao.certsToIssuer, cert)
		}
	}
	delete(ao.issuerToCerts, issuer)
}

// Certificates returns all certificates for the given issuer.
func (ao *AssociatedObjects) Certificates(issuer IssuerKey) []client.ObjectKey {
	ao.lock.Lock()
	defer ao.lock.Unlock()

	set := ao.issuerToCerts[issuer]
	if set == nil {
		return nil
	}
	return set.UnsortedList()
}

// CertificateCount counts the certificates for the given issuer.
func (ao *AssociatedObjects) CertificateCount(issuer IssuerKey) int {
	ao.lock.Lock()
	defer ao.lock.Unlock()

	set := ao.issuerToCerts[issuer]
	if set == nil {
		return 0
	}
	return len(set)
}

// AllIssuers returns all sources.
func (ao *AssociatedObjects) AllIssuers() []IssuerKey {
	ao.lock.Lock()
	defer ao.lock.Unlock()

	sources := []IssuerKey{}
	for issuer := range ao.issuerToCerts {
		sources = append(sources, issuer)
	}
	return sources
}

/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package core

import (
	"sync"

	"github.com/gardener/controller-manager-library/pkg/resources"

	"github.com/gardener/cert-management/pkg/cert/utils"
)

// NewAssociatedObjects creates an AssociatedObjects
func NewAssociatedObjects() *AssociatedObjects {
	return &AssociatedObjects{
		srcToDest: map[utils.IssuerKey]resources.ObjectNameSet{},
		destToSrc: map[resources.ObjectName]utils.IssuerKey{},
	}
}

// AssociatedObjects stores bidi-associations between source and dest.
type AssociatedObjects struct {
	lock      sync.Mutex
	srcToDest map[utils.IssuerKey]resources.ObjectNameSet
	destToSrc map[resources.ObjectName]utils.IssuerKey
}

// AddAssoc adds an association.
func (ao *AssociatedObjects) AddAssoc(src utils.IssuerKey, dst resources.ObjectName) {
	ao.lock.Lock()
	defer ao.lock.Unlock()

	set := ao.srcToDest[src]
	if set == nil {
		set = resources.ObjectNameSet{}
		ao.srcToDest[src] = set
	}
	set.Add(dst)
	ao.destToSrc[dst] = src
}

// RemoveByDest removes an association by dest.
func (ao *AssociatedObjects) RemoveByDest(dst resources.ObjectName) {
	ao.lock.Lock()
	defer ao.lock.Unlock()

	if src, ok := ao.destToSrc[dst]; ok {
		if set := ao.srcToDest[src]; set != nil {
			set.Remove(dst)
			if len(set) == 0 {
				delete(ao.srcToDest, src)
			}
		}
		delete(ao.destToSrc, dst)
	}
}

// RemoveBySource removes an association by src.
func (ao *AssociatedObjects) RemoveBySource(src utils.IssuerKey) {
	ao.lock.Lock()
	defer ao.lock.Unlock()

	if set := ao.srcToDest[src]; set != nil {
		for dst := range set {
			delete(ao.destToSrc, dst)
		}
	}
	delete(ao.srcToDest, src)
}

// DestinationsAsArray returns all destinations for the given source.
func (ao *AssociatedObjects) DestinationsAsArray(src utils.IssuerKey) []resources.ObjectName {
	ao.lock.Lock()
	defer ao.lock.Unlock()

	set := ao.srcToDest[src]
	if set == nil {
		return nil
	}
	return set.AsArray()
}

// DestinationsCount counts the destinations for the given source.
func (ao *AssociatedObjects) DestinationsCount(src utils.IssuerKey) int {
	ao.lock.Lock()
	defer ao.lock.Unlock()

	set := ao.srcToDest[src]
	if set == nil {
		return 0
	}
	return len(set)
}

// Sources returns all sources.
func (ao *AssociatedObjects) Sources() []utils.IssuerKey {
	ao.lock.Lock()
	defer ao.lock.Unlock()

	sources := []utils.IssuerKey{}
	for src := range ao.srcToDest {
		sources = append(sources, src)
	}
	return sources
}

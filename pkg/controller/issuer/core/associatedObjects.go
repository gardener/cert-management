/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package core

import (
	"sync"

	"github.com/gardener/controller-manager-library/pkg/resources"
)

// NewAssociatedObjects creates an AssociatedObjects
func NewAssociatedObjects() *AssociatedObjects {
	return &AssociatedObjects{
		srcToDest: map[resources.ObjectName]resources.ObjectNameSet{},
		destToSrc: map[resources.ObjectName]resources.ObjectName{},
	}
}

// AssociatedObjects stores bidi-associations between source and dest.
type AssociatedObjects struct {
	lock      sync.Mutex
	srcToDest map[resources.ObjectName]resources.ObjectNameSet
	destToSrc map[resources.ObjectName]resources.ObjectName
}

// AddAssoc adds an association.
func (ao *AssociatedObjects) AddAssoc(src, dst resources.ObjectName) {
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

	if src := ao.destToSrc[dst]; src != nil {
		set := ao.srcToDest[src]
		if set != nil {
			set.Remove(dst)
			if len(set) == 0 {
				delete(ao.srcToDest, src)
			}
		}
		delete(ao.destToSrc, dst)
	}
}

// RemoveBySource removes an association by src.
func (ao *AssociatedObjects) RemoveBySource(src resources.ObjectName) {
	ao.lock.Lock()
	defer ao.lock.Unlock()

	for dst := range ao.srcToDest[src] {
		delete(ao.destToSrc, dst)
	}
	delete(ao.srcToDest, src)
}

// DestinationsAsArray returns all destinations for the given source.
func (ao *AssociatedObjects) DestinationsAsArray(src resources.ObjectName) []resources.ObjectName {
	ao.lock.Lock()
	defer ao.lock.Unlock()

	set := ao.srcToDest[src]
	if set == nil {
		return nil
	}
	return set.AsArray()
}

// DestinationsCount counts the destinations for the given source.
func (ao *AssociatedObjects) DestinationsCount(src resources.ObjectName) int {
	ao.lock.Lock()
	defer ao.lock.Unlock()

	set := ao.srcToDest[src]
	if set == nil {
		return 0
	}
	return len(set)
}

// Sources returns all sources.
func (ao *AssociatedObjects) Sources() []resources.ObjectName {
	ao.lock.Lock()
	defer ao.lock.Unlock()

	sources := []resources.ObjectName{}
	for src := range ao.srcToDest {
		sources = append(sources, src)
	}
	return sources
}

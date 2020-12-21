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

// newObjectNameSet creates a synced ObjectNameSet
func newObjectNameSet() *objectNameSet {
	return &objectNameSet{
		set: resources.ObjectNameSet{},
	}
}

// objectNameSet is a synced ObjectNameSet.
type objectNameSet struct {
	lock sync.Mutex
	set  resources.ObjectNameSet
}

// Add a name.
func (s *objectNameSet) Add(name resources.ObjectName) bool {
	s.lock.Lock()
	defer s.lock.Unlock()

	old := len(s.set)
	s.set.Add(name)
	return len(s.set) != old
}

// Remove a name.
func (s *objectNameSet) Remove(name resources.ObjectName) bool {
	s.lock.Lock()
	defer s.lock.Unlock()

	old := len(s.set)
	s.set.Remove(name)
	return len(s.set) != old
}

// AsArray returns copy of members as array
func (s *objectNameSet) AsArray() []resources.ObjectName {
	s.lock.Lock()
	defer s.lock.Unlock()

	return s.set.AsArray()
}

func (s *objectNameSet) String() string {
	s.lock.Lock()
	defer s.lock.Unlock()

	return s.set.String()
}

func (s *objectNameSet) Size() int {
	s.lock.Lock()
	defer s.lock.Unlock()

	return len(s.set)
}

/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package core

import (
	"sort"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// newObjectKeySet creates a synced Set[client.ObjectKey]
func newObjectKeySet() *objectKeySet {
	return &objectKeySet{
		set: sets.Set[client.ObjectKey]{},
	}
}

// objectKeySet is a synced ObjectNameSet.
type objectKeySet struct {
	lock sync.Mutex
	set  sets.Set[client.ObjectKey]
}

// Add a name.
func (s *objectKeySet) Add(key client.ObjectKey) bool {
	s.lock.Lock()
	defer s.lock.Unlock()

	old := len(s.set)
	s.set.Insert(key)
	return len(s.set) != old
}

// Remove a name.
func (s *objectKeySet) Remove(key client.ObjectKey) bool {
	s.lock.Lock()
	defer s.lock.Unlock()

	oldLen := len(s.set)
	return len(s.set.Delete(key)) != oldLen
}

// UnsortedList returns copy of members as array
func (s *objectKeySet) UnsortedList() []client.ObjectKey {
	s.lock.Lock()
	defer s.lock.Unlock()

	return s.set.UnsortedList()
}

func (s *objectKeySet) String() string {
	s.lock.Lock()
	defer s.lock.Unlock()

	array := s.UnsortedList()
	sort.Slice(s, func(i, j int) bool {
		if array[i].Namespace < array[j].Namespace {
			return true
		} else if array[i].Namespace > array[j].Namespace {
			return false
		} else {
			return array[i].Name < array[j].Name
		}
	})
	strs := make([]string, len(array))
	for i, obj := range array {
		strs[i] = obj.String()
	}
	return strings.Join(strs, ",")
}

func (s *objectKeySet) Size() int {
	s.lock.Lock()
	defer s.lock.Unlock()

	return len(s.set)
}

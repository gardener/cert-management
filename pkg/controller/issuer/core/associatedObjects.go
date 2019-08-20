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
)

func NewAssociatedObjects() *AssociatedObjects {
	return &AssociatedObjects{
		objects: map[resources.ObjectName]resources.ObjectNameSet{},
	}
}

type AssociatedObjects struct {
	lock    sync.Mutex
	objects map[resources.ObjectName]resources.ObjectNameSet
}

func (ao *AssociatedObjects) AddDest(src, dst resources.ObjectName) {
	ao.lock.Lock()
	defer ao.lock.Unlock()

	set := ao.objects[src]
	if set == nil {
		set = resources.ObjectNameSet{}
		ao.objects[src] = set
	}
	set.Add(dst)
}

func (ao *AssociatedObjects) RemoveDest(src, dst resources.ObjectName) {
	ao.lock.Lock()
	defer ao.lock.Unlock()

	set := ao.objects[src]
	if set == nil {
		return
	}
	set.Remove(dst)
}

func (ao *AssociatedObjects) RemoveSource(src resources.ObjectName) {
	ao.lock.Lock()
	defer ao.lock.Unlock()

	delete(ao.objects, src)
}

func (ao *AssociatedObjects) DestinationsAsArray(src resources.ObjectName) []resources.ObjectName {
	ao.lock.Lock()
	defer ao.lock.Unlock()

	set, ok := ao.objects[src]
	if !ok {
		return nil
	}
	return set.AsArray()
}

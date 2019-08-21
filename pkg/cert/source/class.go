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

package source

import (
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/controller-manager-library/pkg/utils"
	"strings"
)

type Classes struct {
	classes utils.StringSet
	main    string
}

func NewClasses(classes string) *Classes {
	c := &Classes{classes: utils.StringSet{}}
	if classes == "" {
		c.main = DefaultClass
		c.classes.Add(c.main)
	} else {
		c.classes.AddAllSplitted(classes)
		index := strings.Index(classes, ",")
		if index < 0 {
			c.main = strings.ToLower(strings.TrimSpace(classes))
		} else {
			c.main = strings.ToLower(strings.TrimSpace(classes[:index]))
		}
	}
	return c
}

func (this *Classes) String() string {
	return this.classes.String()
}

func (this *Classes) Main() string {
	return this.main
}

func (this *Classes) Classes() utils.StringSet {
	return this.classes.Copy()
}

func (this *Classes) Contains(class string) bool {
	return this.classes.Contains(class)
}

func (this *Classes) GetAnnotatedClass(obj resources.Object) string {
	oclass, ok := resources.GetAnnotation(obj.Data(), ANNOT_CLASS)
	if !ok {
		oclass = DefaultClass
	}
	return oclass
}

func (this *Classes) IsResponsibleFor(logger logger.LogContext, obj resources.Object) bool {
	oclass := this.GetAnnotatedClass(obj)
	if !this.classes.Contains(oclass) {
		logger.Debugf("%s: annotated cert class %q does not match specified class set %s -> skip ",
			obj.ObjectName(), oclass, this.classes)
		return false
	}
	return true
}

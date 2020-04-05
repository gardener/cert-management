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
	"strings"

	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
)

func (r *sourceReconciler) getCertsInfo(logger logger.LogContext, obj resources.Object, s CertSource, current *CertCurrentState) (*CertsInfo, error) {
	if !r.classes.IsResponsibleFor(logger, obj) {
		return nil, nil
	}
	info, err := s.GetCertsInfo(logger, obj, current)
	return info, err
}

// DomainsString returns all domains as comma separated string (common name and DNS names)
func (info CertInfo) DomainsString() string {
	return DomainsString(info.Domains)
}

// DomainsString creates a comma separated string.
func DomainsString(domains []string) string {
	if domains == nil {
		return ""
	}
	return strings.Join(domains, ",")
}

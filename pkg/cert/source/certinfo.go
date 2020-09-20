/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
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

/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package service

import (
	"fmt"

	api "k8s.io/api/core/v1"

	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"

	"github.com/gardener/cert-management/pkg/cert/source"
)

// GetSecretName finds the secret name from the object annotations
func GetSecretName(_ logger.LogContext, objData resources.ObjectData) (string, error) {
	svc := objData.(*api.Service)
	if svc.Spec.Type != api.ServiceTypeLoadBalancer {
		return "", fmt.Errorf("service is not of type LoadBalancer")
	}

	secretName, _ := resources.GetAnnotation(svc, source.AnnotSecretname)
	if secretName == "" {
		return "", fmt.Errorf("Missing annotation '%s'", source.AnnotSecretname)
	}
	return secretName, nil
}

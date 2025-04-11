/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package service

import (
	"fmt"

	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/gardener/cert-management/pkg/cert/source"
)

// GetSecretName finds the secret name from the object annotations
func GetSecretName(_ logger.LogContext, objData resources.ObjectData) (types.NamespacedName, error) {
	var zero types.NamespacedName
	svc := objData.(*api.Service)
	if svc.Spec.Type != api.ServiceTypeLoadBalancer {
		return zero, fmt.Errorf("service is not of type LoadBalancer")
	}

	secretName, _ := resources.GetAnnotation(svc, source.AnnotSecretname)
	if secretName == "" {
		return zero, fmt.Errorf("missing annotation '%s'", source.AnnotSecretname)
	}
	secretNamespace, _ := resources.GetAnnotation(svc, source.AnnotSecretNamespace)
	if secretNamespace == "" {
		secretNamespace = svc.GetNamespace()
	}
	return types.NamespacedName{Namespace: secretNamespace, Name: secretName}, nil
}

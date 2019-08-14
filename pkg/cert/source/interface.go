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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
)

type CertInfo struct {
	SecretName string
	Domains    []string
	IssuerName *string
}

type CertsInfo struct {
	Certs    map[string]CertInfo
	Feedback CertFeedback
}

type CertFeedback interface {
	Succeeded()
	Pending(info *CertInfo, msg string)
	Ready(info *CertInfo, msg string)
	Failed(info *CertInfo, err error)
}

type CertSource interface {
	Start()
	Setup()

	GetCertsInfo(logger logger.LogContext, obj resources.Object, current *CertCurrentState) (*CertsInfo, error)

	Delete(logger logger.LogContext, obj resources.Object) reconcile.Status
	Deleted(logger logger.LogContext, key resources.ClusterObjectKey)
}

type CertSourceType interface {
	Name() string
	GroupKind() schema.GroupKind
	Create(controller.Interface) (CertSource, error)
}

type CertTargetExtractor func(logger logger.LogContext, obj resources.Object, current *CertCurrentState) (string, error)
type CertSourceCreator func(controller.Interface) (CertSource, error)

type CertState struct {
	Spec              api.CertificateSpec
	State             string
	Message           *string
	CreationTimestamp metav1.Time
}

type CertCurrentState struct {
	CertStates map[string]*CertState
}

func (s *CertCurrentState) ContainsSecretName(name string) bool {
	_, ok := s.CertStates[name]
	return ok
}

func NewCertSourceTypeForExtractor(name string, kind schema.GroupKind, handler CertTargetExtractor) CertSourceType {
	return &handlercertsourcetype{certsourcetype{name, kind}, NewDefaultCertSource(handler, kind)}
}

func NewCertSourceTypeForCreator(name string, kind schema.GroupKind, handler CertSourceCreator) CertSourceType {
	return &creatorcertsourcetype{certsourcetype{name, kind}, handler}
}

type certsourcetype struct {
	name string
	kind schema.GroupKind
}

type handlercertsourcetype struct {
	certsourcetype
	DefaultCertSource
}

type creatorcertsourcetype struct {
	certsourcetype
	handler CertSourceCreator
}

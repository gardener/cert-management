/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package source

import (
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
)

// CertInfo contains basic certificate data.
type CertInfo struct {
	SecretName          types.NamespacedName
	Domains             []string
	IssuerName          *string
	FollowCNAME         bool
	SecretLabels        map[string]string
	PreferredChain      string
	PrivateKeyAlgorithm string
	PrivateKeySize      api.PrivateKeySize
	Annotations         map[string]string
}

// CertsInfo contains a map of CertInfo.
type CertsInfo struct {
	Certs map[types.NamespacedName]CertInfo
}

// CertFeedback is an interface for reporting certificate status.
type CertFeedback interface {
	Succeeded()
	Pending(info *CertInfo, msg string)
	Ready(info *CertInfo, msg string)
	Failed(info *CertInfo, err error)
}

// CertSource is...
type CertSource interface {
	Start() error
	Setup() error

	CreateCertFeedback(logger logger.LogContext, obj resources.Object) CertFeedback
	GetCertsInfo(logger logger.LogContext, objData resources.ObjectData) (*CertsInfo, error)

	Delete(logger logger.LogContext, obj resources.Object) reconcile.Status
	Deleted(logger logger.LogContext, key resources.ClusterObjectKey)
}

// CertSourceType provides basic functionalilty.
type CertSourceType interface {
	Name() string
	GroupKind() schema.GroupKind
	Create(controller.Interface) (CertSource, error)
}

// CertTargetExtractor is type for extractor.
type CertTargetExtractor func(logger logger.LogContext, objData resources.ObjectData) (types.NamespacedName, error)

// CertSourceCreator is type for creator.
type CertSourceCreator func(controller.Interface) (CertSource, error)

// CertState contains internal certificate state.
type CertState struct {
	// Spec is original spec from CR.
	Spec api.CertificateSpec
	// State is the state string.
	State string
	// Message is the optional status or error message.
	Message *string
	// CreationTimestamp contains the creation timestamp of the certificate.
	CreationTimestamp metav1.Time
}

// CertCurrentState contains the current state.
type CertCurrentState struct {
	CertStates map[types.NamespacedName]*CertState
}

// ContainsSecretName returns true if secret name is in map.
func (s *CertCurrentState) ContainsSecretName(name types.NamespacedName) bool {
	_, ok := s.CertStates[name]
	return ok
}

// NewCertSourceTypeForExtractor creates CertSourceType for extractor.
func NewCertSourceTypeForExtractor(name string, kind schema.GroupKind, handler CertTargetExtractor) CertSourceType {
	return &handlercertsourcetype{certsourcetype{name, kind}, NewDefaultCertSource(handler)}
}

// NewCertSourceTypeForCreator creates CertSourceType for creator.
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

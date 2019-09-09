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
	"fmt"
	"github.com/gardener/cert-management/pkg/cert/utils"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/cert/legobridge"
	ctrl "github.com/gardener/cert-management/pkg/controller"
)

type Enqueuer interface {
	EnqueueKey(key resources.ClusterObjectKey) error
}

type IssuerHandlerFactory func(support *Support) (IssuerHandler, error)

type IssuerHandler interface {
	Type() string
	CanReconcile(issuer *api.Issuer) bool
	Reconcile(logger logger.LogContext, obj resources.Object, issuer *api.Issuer) reconcile.Status
}

func NewHandlerSupport(c controller.Interface, factories ...IssuerHandlerFactory) (*CompoundHandler, *Support, error) {
	defaultCluster := c.GetCluster(ctrl.DefaultCluster)
	targetCluster := c.GetCluster(ctrl.TargetCluster)
	issuerResources, err := defaultCluster.Resources().GetByExample(&api.Issuer{})
	if err != nil {
		return nil, nil, err
	}
	issuerSecretResources, err := defaultCluster.Resources().GetByExample(&corev1.Secret{})
	if err != nil {
		return nil, nil, err
	}

	state := newState()
	s := &Support{
		enqueuer:              c,
		state:                 state,
		issuerResources:       issuerResources,
		issuerSecretResources: issuerSecretResources,
		defaultCluster:        defaultCluster,
		targetCluster:         targetCluster,
	}

	s.defaultIssuerName, _ = c.GetStringOption(OptDefaultIssuer)
	s.issuerNamespace, _ = c.GetStringOption(OptIssuerNamespace)
	s.defaultIssuerDomainRange, _ = c.GetStringOption(OptDefaultIssuerDomainRange)
	s.defaultIssuerDomainRange = utils.NormalizeDomainRange(s.defaultIssuerDomainRange)

	h := &CompoundHandler{support: s}
	err = h.addIssuerHandlerFactories(factories)
	if err != nil {
		return nil, nil, err
	}

	return h, s, nil
}

type CompoundHandler struct {
	support  *Support
	handlers []IssuerHandler
}

func (h *CompoundHandler) ReconcileIssuer(logger logger.LogContext, obj resources.Object) reconcile.Status {
	logger.Infof("reconciling")
	issuer, ok := obj.Data().(*api.Issuer)
	if !ok {
		return h.failedNoType(logger, obj, api.STATE_ERROR, fmt.Errorf("casting to issuer failed"))
	}
	for _, handler := range h.handlers {
		if handler.CanReconcile(issuer) {
			return handler.Reconcile(logger, obj, issuer)
		}
	}
	return h.failedNoType(logger, obj, api.STATE_ERROR, fmt.Errorf("concrete issuer unspecified"))
}

func (h *CompoundHandler) DeletedIssuer(logger logger.LogContext, key resources.ClusterObjectKey) reconcile.Status {
	h.support.RemoveIssuer(key.ObjectName())
	logger.Infof("deleted")
	return reconcile.Succeeded(logger)
}

func (h *CompoundHandler) ReconcileSecret(logger logger.LogContext, obj resources.Object) reconcile.Status {
	return h.enqueueIssuers(logger, obj.ObjectName())
}

func (h *CompoundHandler) DeletedSecret(logger logger.LogContext, key resources.ClusterObjectKey) reconcile.Status {
	return h.enqueueIssuers(logger, key.ObjectName())
}

func (h *CompoundHandler) failedNoType(logger logger.LogContext, obj resources.Object, state string, err error) reconcile.Status {
	return h.support.Failed(logger, obj, state, nil, err)

}

func (h *CompoundHandler) addIssuerHandlerFactories(factories []IssuerHandlerFactory) error {
	for _, factory := range factories {
		handler, err := factory(h.support)
		if err != nil {
			return err
		}
		h.handlers = append(h.handlers, handler)
	}
	return nil
}

func (h *CompoundHandler) enqueueIssuers(logger logger.LogContext, objName resources.ObjectName) reconcile.Status {
	issuers := h.support.IssuerNamesForSecret(objName)
	if issuers != nil {
		groupKind := api.Kind(api.IssuerKind)
		clusterId := h.support.GetDefaultClusterId()
		for issuerName := range issuers {
			key := resources.NewClusterKey(clusterId, groupKind, issuerName.Namespace(), issuerName.Name())
			_ = h.support.EnqueueKey(key)
		}
	}
	return reconcile.Succeeded(logger)
}

type Support struct {
	enqueuer                 Enqueuer
	state                    *state
	defaultCluster           resources.Cluster
	targetCluster            resources.Cluster
	issuerResources          resources.Interface
	issuerSecretResources    resources.Interface
	defaultIssuerName        string
	issuerNamespace          string
	defaultIssuerDomainRange string
}

func (s *Support) EnqueueKey(key resources.ClusterObjectKey) error {
	return s.enqueuer.EnqueueKey(key)
}

func (s *Support) WriteIssuerSecretFromRegistrationUser(issuer metav1.ObjectMeta, reguser *legobridge.RegistrationUser,
	secretName string) (*corev1.SecretReference, error) {
	var err error

	secret := &corev1.Secret{}
	if secretName != "" {
		secret.SetName(secretName)
	} else {
		secret.SetGenerateName(issuer.GetName() + "-")
	}
	namespace := "default"
	if issuer.GetNamespace() != "" {
		namespace = issuer.GetNamespace()
	}
	secret.SetNamespace(namespace)
	secret.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: api.Version, Kind: api.IssuerKind, Name: issuer.Name, UID: issuer.GetUID()}})
	secret.Data, err = reguser.ToSecretData()
	if err != nil {
		return nil, err
	}

	obj, err := s.defaultCluster.Resources().CreateOrUpdateObject(secret)
	if err != nil {
		return nil, fmt.Errorf("creating/updating issuer secret failed with %s", err.Error())
	}

	return &corev1.SecretReference{Name: obj.GetName(), Namespace: secret.GetNamespace()}, nil
}

func (s *Support) UpdateIssuerSecret(issuer metav1.ObjectMeta, reguser *legobridge.RegistrationUser,
	secret *corev1.Secret) error {
	var err error
	secret.Data, err = reguser.ToSecretData()
	if err != nil {
		return err
	}
	obj, err := s.defaultCluster.Resources().Wrap(secret)
	if err != nil {
		return fmt.Errorf("wrapping issuer secret failed with %s", err.Error())
	}
	err = obj.Update()
	if err != nil {
		return fmt.Errorf("updating issuer secret failed with %s", err.Error())
	}

	return nil
}

func (s *Support) ReadIssuerSecret(ref *corev1.SecretReference) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	itf, err := s.defaultCluster.Resources().GetByExample(secret)
	if err != nil {
		return nil, err
	}

	objName := resources.NewObjectName(ref.Namespace, ref.Name)
	_, err = itf.GetInto(objName, secret)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func (s *Support) triggerCertificates(logger logger.LogContext, issuerName resources.ObjectName) {
	array := s.state.CertificateNamesForIssuer(issuerName)
	clusterId := s.targetCluster.GetId()
	if len(array) > 0 {
		logger.Infof("Trigger reconcile for %d certificates of issuer %s", len(array), issuerName)
		for _, objName := range array {
			key := resources.NewClusterKey(clusterId, api.Kind(api.CertificateKind), objName.Namespace(), objName.Name())
			_ = s.enqueuer.EnqueueKey(key)
		}
	}
}

func (s *Support) prepareUpdateStatus(obj resources.Object, state string, itype *string, msg *string) (*resources.ModificationState, *api.IssuerStatus) {
	crt := obj.Data().(*api.Issuer)
	status := &crt.Status

	mod := resources.NewModificationState(obj)
	mod.AssureStringPtrPtr(&status.Message, msg)
	mod.AssureStringPtrPtr(&status.Type, itype)
	mod.AssureStringValue(&status.State, state)
	mod.AssureInt64Value(&status.ObservedGeneration, obj.GetGeneration())

	return mod, status
}

func (s *Support) updateStatus(mod *resources.ModificationState) {
	err := mod.UpdateStatus()
	if err != nil {
		logger.Warnf("updating status failed with: %s", err)
	}
}

func (s *Support) Failed(logger logger.LogContext, obj resources.Object, state string, itype *string, err error) reconcile.Status {
	msg := err.Error()

	mod, _ := s.prepareUpdateStatus(obj, state, itype, &msg)
	s.updateStatus(mod)

	return reconcile.Failed(logger, err)
}

func (s *Support) SucceededAndTriggerCertificates(logger logger.LogContext, obj resources.Object, itype *string) reconcile.Status {
	s.triggerCertificates(logger, obj.ObjectName())
	return s.Succeeded(logger, obj, itype, nil)
}

func (s *Support) Succeeded(logger logger.LogContext, obj resources.Object, itype *string, msg *string) reconcile.Status {
	mod, _ := s.prepareUpdateStatus(obj, api.STATE_READY, itype, msg)
	s.updateStatus(mod)

	return reconcile.Succeeded(logger)
}

func (s *Support) AddCertificate(logger logger.LogContext, cert *api.Certificate) {
	certObjName, issuerObjName := s.calcAssocObjectNames(cert)
	s.state.AddCertAssoc(issuerObjName, certObjName)
}

func (s *Support) RemoveCertificate(logger logger.LogContext, certObjName resources.ObjectName) {
	s.state.RemoveCertAssoc(certObjName)
}

func (s *Support) calcAssocObjectNames(cert *api.Certificate) (resources.ObjectName, resources.ObjectName) {
	certObjName := newObjectName(cert.Namespace, cert.Name)

	issuerName := s.defaultIssuerName
	if cert.Spec.IssuerRef != nil {
		issuerName = cert.Spec.IssuerRef.Name
	}
	return certObjName, newObjectName(cert.Namespace, issuerName)
}

func newObjectName(namespace, name string) resources.ObjectName {
	if namespace == "" {
		namespace = "default"
	}
	return resources.NewObjectName(namespace, name)
}

func (s *Support) DefaultIssuerName() string {
	return s.defaultIssuerName
}

func (s *Support) IssuerNamespace() string {
	return s.issuerNamespace
}

func (s *Support) DefaultIssuerDomainRange() string {
	return s.defaultIssuerDomainRange
}

func (s *Support) CertificateNamesForIssuer(issuer resources.ObjectName) []resources.ObjectName {
	return s.state.CertificateNamesForIssuer(issuer)
}

func (s *Support) IssuerNamesForSecret(secretName resources.ObjectName) resources.ObjectNameSet {
	return s.state.IssuerNamesForSecret(secretName)
}

func (s *Support) RememberIssuerSecret(issuer resources.ObjectName, secretRef *corev1.SecretReference) {
	s.state.RememberIssuerSecret(issuer, secretRef)
}

func (s *Support) RemoveIssuer(name resources.ObjectName) bool {
	return s.state.RemoveIssuer(name)
}

func (s *Support) GetDefaultClusterId() string {
	return s.defaultCluster.GetId()
}

func (s *Support) GetIssuerResources() resources.Interface {
	return s.issuerResources
}

func (s *Support) GetIssuerSecretResources() resources.Interface {
	return s.issuerSecretResources
}

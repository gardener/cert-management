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
	"fmt"
	"strings"
	"time"

	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile/reconcilers"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/controller-manager-library/pkg/utils"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	certutils "github.com/gardener/cert-management/pkg/cert/utils"
	ctrl "github.com/gardener/cert-management/pkg/controller"
)

func SourceReconciler(sourceType CertSourceType, rtype controller.ReconcilerType) controller.ReconcilerType {
	return func(c controller.Interface) (reconcile.Interface, error) {
		s, err := sourceType.Create(c)
		if err != nil {
			return nil, err
		}
		copt, _ := c.GetStringOption(OPT_CLASS)
		classes := controller.NewClasses(c, copt, ANNOT_CLASS, DefaultClass)
		c.SetFinalizerHandler(controller.NewFinalizerForClasses(c, c.GetDefinition().FinalizerName(), classes))
		targetclass, _ := c.GetStringOption(OPT_TARGETCLASS)
		if targetclass == "" {
			if !classes.Contains(DefaultClass) && classes.Main() != DefaultClass {
				targetclass = classes.Main()
			}
		}
		c.Infof("responsible for classes: %s (%s)", classes, classes.Main())
		c.Infof("target class           : %s", targetclass)
		reconciler := &sourceReconciler{
			SlaveAccess: reconcilers.NewSlaveAccess(c, sourceType.Name(), SlaveResources, MasterResourcesType(sourceType.GroupKind())),
			source:      s,
			classes:     classes,
			targetclass: targetclass,
		}

		reconciler.namespace, _ = c.GetStringOption(OPT_NAMESPACE)
		reconciler.nameprefix, _ = c.GetStringOption(OPT_NAMEPREFIX)

		if c.GetMainCluster() == c.GetCluster(ctrl.TargetCluster) {
			reconciler.namespace = ""
			reconciler.nameprefix = ""
		}

		nested, err := reconcilers.NewNestedReconciler(rtype, reconciler)
		if err != nil {
			return nil, err
		}
		reconciler.NestedReconciler = nested
		return reconciler, nil
	}
}

type sourceReconciler struct {
	*reconcilers.NestedReconciler
	*reconcilers.SlaveAccess
	source      CertSource
	classes     *controller.Classes
	targetclass string
	namespace   string
	nameprefix  string
}

func (this *sourceReconciler) Start() {
	this.SlaveAccess.Start()
	this.source.Start()
	this.NestedReconciler.Start()
}

func (this *sourceReconciler) Setup() {
	this.SlaveAccess.Setup()
	this.source.Setup()
	this.NestedReconciler.Setup()
}

func getCertificateSecretName(obj resources.Object) string {
	crt := certutils.Certificate(obj).Certificate()
	if crt.Spec.SecretRef != nil {
		return crt.Spec.SecretRef.Name
	} else if crt.Spec.SecretName != nil {
		return *crt.Spec.SecretName
	}
	panic("missing secret name")
}

func (this *sourceReconciler) Reconcile(logger logger.LogContext, obj resources.Object) reconcile.Status {
	slaves := this.LookupSlaves(obj.ClusterKey())
	currentState := &CertCurrentState{CertStates: map[string]*CertState{}}
	for _, s := range slaves {
		crt := certutils.Certificate(s).Certificate()
		secretName := getCertificateSecretName(s)
		currentState.CertStates[secretName] = &CertState{Spec: crt.Spec,
			State: crt.Status.State, Message: crt.Status.Message, CreationTimestamp: crt.CreationTimestamp}
	}

	info, err := this.getCertsInfo(logger, obj, this.source, currentState)
	if err != nil {
		obj.Event(core.EventTypeWarning, "reconcile", err.Error())
	}

	if info == nil {
		if err != nil {
			return reconcile.Failed(logger, err)
		}
		return reconcile.Succeeded(logger).Stop()
	}

	if len(info.Certs) > 0 && requireFinalizer(obj, this.SlaveResoures()[0].GetCluster()) {
		err := this.SetFinalizer(obj)
		if err != nil {
			return reconcile.Delay(logger, fmt.Errorf("cannot set finalizer: %s", err))
		}
	} else {
		err := this.RemoveFinalizer(obj)
		if err != nil {
			return reconcile.Delay(logger, fmt.Errorf("cannot remove finalizer: %s", err))
		}
	}

	missingSecretNames := utils.StringSet{}
	for secretName := range info.Certs {
		if !currentState.ContainsSecretName(secretName) {
			missingSecretNames.Add(secretName)
		}
	}

	obsolete := []resources.Object{}
	obsoleteSecretNames := utils.StringSet{}
	current := []resources.Object{}
	for _, s := range slaves {
		secretName := getCertificateSecretName(s)
		if _, ok := info.Certs[secretName]; !ok {
			obsolete = append(obsolete, s)
			obsoleteSecretNames.Add(secretName)
		} else {
			current = append(current, s)
		}
	}

	var notifiedErrors []string
	modified := map[string]bool{}
	if len(missingSecretNames) > 0 {
		logger.Infof("found missing secrets: %s", missingSecretNames)
		for secretName := range missingSecretNames {
			err := this.createEntryFor(logger, obj, info.Certs[secretName], info.Feedback)
			if err != nil {
				notifiedErrors = append(notifiedErrors, fmt.Sprintf("cannot create certificate for secret %s: %s ", secretName, err))
			}
		}
	}

	if len(obsoleteSecretNames) > 0 {
		logger.Infof("found obsolete secrets: %s", obsoleteSecretNames)
		for _, o := range obsolete {
			secretName := getCertificateSecretName(o)
			err := this.deleteEntry(logger, obj, o)
			if err != nil {
				notifiedErrors = append(notifiedErrors, fmt.Sprintf("cannot remove certificate %q for secret %s: %s",
					o.ClusterKey(), secretName, err))
			}
		}
	}

	for _, o := range current {
		secretName := getCertificateSecretName(o)
		mod, err := this.updateEntry(logger, info.Certs[secretName], o)
		modified[secretName] = mod
		if err != nil {
			notifiedErrors = append(notifiedErrors, fmt.Sprintf("cannot update certificate %q for secret %s: %s",
				o.ClusterKey(), secretName, err))
		}
	}

	if len(notifiedErrors) > 0 {
		msg := strings.Join(notifiedErrors, ", ")
		if info.Feedback != nil {
			info.Feedback.Failed(nil, fmt.Errorf("%s", msg))
		}
		return reconcile.Delay(logger, fmt.Errorf("reconcile failed: %s", msg))
	}

	if info.Feedback != nil {
		threshold := time.Now().Add(-2 * time.Minute)
		for secretName, certInfo := range info.Certs {
			s := currentState.CertStates[secretName]
			if s != nil && !modified[secretName] {
				switch s.State {
				case api.STATE_ERROR:
					err := fmt.Errorf("errornous certificate")
					if s.Message != nil {
						err = fmt.Errorf("%s: %s", err, *s.Message)
					}
					info.Feedback.Failed(&certInfo, err)
				case api.STATE_PENDING:
					msg := fmt.Sprintf("certificate pending")
					if s.Message != nil {
						msg = fmt.Sprintf("%s: %s", msg, *s.Message)
					}
					info.Feedback.Pending(&certInfo, msg)
				case api.STATE_READY:
					msg := "certificate ready"
					if s.Message != nil {
						msg = *s.Message
					}
					info.Feedback.Ready(&certInfo, msg)
				default:
					if s.CreationTimestamp.Time.Before(threshold) {
						info.Feedback.Pending(&certInfo, "no certcontrollers running?")
					}
				}
			}
		}
		info.Feedback.Succeeded()
	}

	status := this.NestedReconciler.Reconcile(logger, obj)
	if status.IsSucceeded() {
		if len(info.Certs) == 0 {
			return status.Stop()
		}
	}
	return status
}

// Deleted is used as fallback, if the source object in another cluster is
//  deleted unexpectedly (by removing the finalizer).
//  It checks whether a slave is still available and deletes it.
func (this *sourceReconciler) Deleted(logger logger.LogContext, key resources.ClusterObjectKey) reconcile.Status {
	logger.Infof("%s finally deleted", key)
	failed := false
	for _, s := range this.Slaves().GetByKey(key) {
		err := s.Delete()
		commonName := certutils.Certificate(s).SafeCommonName()
		if err != nil && !errors.IsNotFound(err) {
			logger.Warnf("cannot delete certificate %s(%s): %s", s.ObjectName(), commonName, err)
			failed = true
		} else {
			logger.Infof("delete certificate for vanished %s(%s)", s.ObjectName(), commonName)
		}
	}
	if failed {
		return reconcile.Delay(logger, nil)
	}

	this.source.Deleted(logger, key)
	return this.NestedReconciler.Deleted(logger, key)
}

func (this *sourceReconciler) Delete(logger logger.LogContext, obj resources.Object) reconcile.Status {
	failed := false
	logger.Infof("certificate source is deleting -> delete certificate")
	for _, s := range this.Slaves().Get(obj) {
		commonName := certutils.Certificate(s).SafeCommonName()
		logger.Infof("delete certificate %s(%s)", s.ObjectName(), commonName)
		err := s.Delete()
		if err != nil && !errors.IsNotFound(err) {
			logger.Warnf("cannot delete certificate %s for %s: %s", s.ObjectName(), commonName, err)
			failed = true
		}
	}
	if failed {
		return reconcile.Delay(logger, nil)
	}

	status := this.source.Delete(logger, obj)
	if status.IsSucceeded() {
		status = this.NestedReconciler.Delete(logger, obj)
		if status.IsSucceeded() {
			err := this.RemoveFinalizer(obj)
			if err != nil {
				return reconcile.Delay(logger, err)
			}
		}
	}

	return status
}

////////////////////////////////////////////////////////////////////////////////

func (this *sourceReconciler) createEntryFor(logger logger.LogContext, obj resources.Object, info CertInfo, feedback CertFeedback) error {
	cert := &api.Certificate{}
	cert.GenerateName = strings.ToLower(this.nameprefix + obj.GetName() + "-" + obj.GroupKind().Kind + "-")
	if this.targetclass != "" {
		cert.SetAnnotations(map[string]string{ANNOT_CLASS: this.targetclass})
	}
	if len(info.Domains) >= 0 {
		cert.Spec.CommonName = &info.Domains[0]
		cert.Spec.DNSNames = info.Domains[1:]
	}
	if info.IssuerName != nil {
		cert.Spec.IssuerRef = &api.IssuerRef{*info.IssuerName}
	}
	cert.Spec.SecretName = &info.SecretName
	if this.namespace == "" {
		cert.Namespace = obj.GetNamespace()
	} else {
		cert.Namespace = this.namespace
	}

	e, _ := this.SlaveResoures()[0].Wrap(cert)

	err := this.Slaves().CreateSlave(obj, e)
	if err != nil {
		if feedback != nil {
			feedback.Failed(&info, err)
		}
		return err
	}
	obj.Eventf(core.EventTypeNormal, "reconcile", "created certificate object %s", e.ObjectName())
	logger.Infof("created certificate object %s", e.ObjectName())
	if feedback != nil {
		feedback.Pending(&info, "")
	}
	return nil
}

func (this *sourceReconciler) deleteEntry(logger logger.LogContext, obj resources.Object, e resources.Object) error {
	err := e.Delete()
	if err == nil {
		obj.Eventf(core.EventTypeNormal, "reconcile", "deleted certificate object %s", e.ObjectName())
		logger.Infof("deleted certificate object %s", e.ObjectName())
	} else {
		if !errors.IsNotFound(err) {
			logger.Errorf("cannot delete certificate object %s: %s", e.ObjectName(), err)
		} else {
			err = nil
		}
	}
	return err
}

func (this *sourceReconciler) updateEntry(logger logger.LogContext, info CertInfo, obj resources.Object) (bool, error) {
	f := func(o resources.ObjectData) (bool, error) {
		spec := &o.(*api.Certificate).Spec
		mod := &utils.ModificationState{}
		var changed bool
		if this.targetclass == "" {
			changed = resources.RemoveAnnotation(o, ANNOT_CLASS)
		} else {
			changed = resources.SetAnnotation(o, ANNOT_CLASS, this.targetclass)
		}
		mod.Modify(changed)
		var cn *string
		var dnsNames []string
		if len(info.Domains) >= 0 {
			cn = &info.Domains[0]
			dnsNames = info.Domains[1:]
		}

		mod.AssureStringPtrPtr(&spec.CommonName, cn)
		certutils.AssureStringArray(mod, &spec.DNSNames, dnsNames)
		if info.IssuerName != nil {
			if spec.IssuerRef == nil || spec.IssuerRef.Name != *info.IssuerName {
				spec.IssuerRef = &api.IssuerRef{*info.IssuerName}
				mod.Modify(true)
			}
		} else {
			if spec.IssuerRef != nil {
				spec.IssuerRef = nil
				mod.Modify(true)
			}
		}
		if mod.IsModified() {
			logger.Infof("update certificate object %s", obj.ObjectName())
		}
		return mod.IsModified(), nil
	}
	return obj.Modify(f)
}

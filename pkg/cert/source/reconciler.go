/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package source

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile/reconcilers"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/controller-manager-library/pkg/resources/abstract"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	certutils "github.com/gardener/cert-management/pkg/cert/utils"
	ctrl "github.com/gardener/cert-management/pkg/controller"
)

// SrcReconciler creates a source reconciler.
func SrcReconciler(sourceType CertSourceType, rtype controller.ReconcilerType) controller.ReconcilerType {
	return func(c controller.Interface) (reconcile.Interface, error) {
		s, err := sourceType.Create(c)
		if err != nil {
			return nil, err
		}
		copt, _ := c.GetStringOption(OptClass)
		classes := controller.NewClasses(c, copt, AnnotClass, DefaultClass)
		c.SetFinalizerHandler(controller.NewFinalizerForClasses(c, c.GetDefinition().FinalizerName(), classes))
		targetclass, _ := c.GetStringOption(OptTargetclass)
		if targetclass == "" {
			if !classes.Contains(DefaultClass) && classes.Main() != DefaultClass {
				targetclass = classes.Main()
			}
		}
		c.Infof("responsible for classes: %s (%s)", classes, classes.Main())
		c.Infof("target class           : %s", targetclass)
		slaveAccess, err := reconcilers.NewSlaveAccess(c, sourceType.Name(), slaveResources, MasterResourcesType(sourceType.GroupKind()))
		if err != nil {
			return nil, err
		}
		reconciler := &sourceReconciler{
			SlaveAccess: slaveAccess,
			source:      s,
			classes:     classes,
			targetclass: targetclass,
		}

		reconciler.namespace, _ = c.GetStringOption(OptNamespace)
		reconciler.nameprefix, _ = c.GetStringOption(OptNameprefix)

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

func (r *sourceReconciler) Start() error {
	if err := r.source.Start(); err != nil {
		return err
	}
	return r.NestedReconciler.Start()
}

func (r *sourceReconciler) Setup() error {
	r.SlaveAccess.Setup()
	if err := r.source.Setup(); err != nil {
		return err
	}
	return r.NestedReconciler.Setup()
}

func getCertificateSecretName(obj resources.Object) (types.NamespacedName, error) {
	crt := certutils.Certificate(obj).Certificate()
	if crt.Spec.SecretRef != nil {
		ns := crt.Spec.SecretRef.Namespace
		if ns == "" {
			ns = obj.GetNamespace()
		}
		return types.NamespacedName{Namespace: ns, Name: crt.Spec.SecretRef.Name}, nil
	} else if crt.Spec.SecretName != nil {
		return types.NamespacedName{Namespace: obj.GetNamespace(), Name: *crt.Spec.SecretName}, nil
	}
	return types.NamespacedName{}, fmt.Errorf("missing secret name for %s", obj.GetName())
}

func (r *sourceReconciler) Reconcile(logger logger.LogContext, obj resources.Object) reconcile.Status {
	slaves := r.LookupSlaves(obj.ClusterKey())
	currentState := &CertCurrentState{CertStates: map[types.NamespacedName]*CertState{}}
	for _, s := range slaves {
		crt := certutils.Certificate(s).Certificate()
		secretName, err := getCertificateSecretName(s)
		if err != nil {
			continue
		}
		currentState.CertStates[secretName] = &CertState{
			Spec:  crt.Spec,
			State: crt.Status.State, Message: crt.Status.Message, CreationTimestamp: crt.CreationTimestamp,
		}
	}

	info, feedback, err := r.getCertsInfo(logger, obj, r.source)
	if err != nil {
		obj.Event(core.EventTypeWarning, "reconcile", err.Error())
	}

	if info == nil {
		if err != nil {
			return reconcile.Failed(logger, err)
		}
		return reconcile.Succeeded(logger).Stop()
	}

	if len(info.Certs) > 0 && requireFinalizer(obj, r.SlaveResoures()[0].GetCluster()) {
		err := r.SetFinalizer(obj)
		if err != nil {
			return reconcile.Delay(logger, fmt.Errorf("cannot set finalizer: %s", err))
		}
	} else {
		err := r.RemoveFinalizer(obj)
		if err != nil {
			return reconcile.Delay(logger, fmt.Errorf("cannot remove finalizer: %s", err))
		}
	}

	missingSecretNames := sets.New[types.NamespacedName]()
	for secretName := range info.Certs {
		if !currentState.ContainsSecretName(secretName) {
			missingSecretNames.Insert(secretName)
		}
	}

	obsolete := []resources.Object{}
	obsoleteSecretNames := sets.New[types.NamespacedName]()
	current := []resources.Object{}
	for _, s := range slaves {
		secretName, err := getCertificateSecretName(s)
		if err != nil {
			obsolete = append(obsolete, s)
		} else if _, ok := info.Certs[secretName]; !ok {
			obsolete = append(obsolete, s)
			obsoleteSecretNames.Insert(secretName)
		} else {
			current = append(current, s)
		}
	}

	var notifiedErrors []string
	modified := map[types.NamespacedName]bool{}
	if len(missingSecretNames) > 0 {
		logger.Infof("found missing secrets: %s", missingSecretNames)
		for secretName := range missingSecretNames {
			err := r.createEntryFor(logger, obj, info.Certs[secretName], feedback)
			if err != nil {
				notifiedErrors = append(notifiedErrors, fmt.Sprintf("cannot create certificate for secret %s: %s ", secretName, err))
			}
		}
	}

	if len(obsoleteSecretNames) > 0 {
		logger.Infof("found obsolete secrets: %s", obsoleteSecretNames)
		for _, o := range obsolete {
			secretName, _ := getCertificateSecretName(o)
			err := r.deleteEntry(logger, obj, o)
			if err != nil {
				notifiedErrors = append(notifiedErrors, fmt.Sprintf("cannot remove certificate %q for secret %s: %s",
					o.ClusterKey(), secretName, err))
			}
		}
	}

	for _, o := range current {
		secretName, err := getCertificateSecretName(o)
		if err != nil {
			continue
		}
		mod, err := r.updateEntry(logger, info.Certs[secretName], o)
		modified[secretName] = mod
		if err != nil {
			notifiedErrors = append(notifiedErrors, fmt.Sprintf("cannot update certificate %q for secret %s: %s",
				o.ClusterKey(), secretName, err))
		}
	}

	if len(notifiedErrors) > 0 {
		msg := strings.Join(notifiedErrors, ", ")
		if feedback != nil {
			feedback.Failed(nil, fmt.Errorf("%s", msg))
		}
		return reconcile.Delay(logger, fmt.Errorf("reconcile failed: %s", msg))
	}

	if feedback != nil {
		threshold := time.Now().Add(-2 * time.Minute)
		for secretName, certInfo := range info.Certs {
			s := currentState.CertStates[secretName]
			if s != nil && !modified[secretName] {
				switch s.State {
				case api.StateError:
					err := fmt.Errorf("errornous certificate")
					if s.Message != nil {
						err = fmt.Errorf("%s: %s", err, *s.Message)
					}
					feedback.Failed(&certInfo, err)
				case api.StatePending:
					msg := "certificate pending"
					if s.Message != nil {
						msg = fmt.Sprintf("%s: %s", msg, *s.Message)
					}
					feedback.Pending(&certInfo, msg)
				case api.StateReady:
					msg := "certificate ready"
					if s.Message != nil {
						msg = *s.Message
					}
					feedback.Ready(&certInfo, msg)
				default:
					if s.CreationTimestamp.Time.Before(threshold) {
						feedback.Pending(&certInfo, "no certcontrollers running?")
					}
				}
			}
		}
		feedback.Succeeded()
	}

	status := r.NestedReconciler.Reconcile(logger, obj)
	if status.IsSucceeded() {
		if len(info.Certs) == 0 {
			return status.Stop()
		}
	}
	return status
}

// Deleted is used as fallback, if the source object in another cluster is
// deleted unexpectedly (by removing the finalizer).
// It checks whether a slave is still available and deletes it.
func (r *sourceReconciler) Deleted(logger logger.LogContext, key resources.ClusterObjectKey) reconcile.Status {
	logger.Infof("%s finally deleted", key)
	failed := false
	for _, s := range r.Slaves().GetByOwnerKey(key) {
		err := s.Delete()
		firstDNSName := certutils.Certificate(s).SafeFirstDNSName()
		if err != nil && !errors.IsNotFound(err) {
			logger.Warnf("cannot delete certificate %s(%s): %s", s.ObjectName(), firstDNSName, err)
			failed = true
		} else {
			logger.Infof("delete certificate for vanished %s(%s)", s.ObjectName(), firstDNSName)
		}
	}
	if failed {
		return reconcile.Delay(logger, nil)
	}

	r.source.Deleted(logger, key)
	return r.NestedReconciler.Deleted(logger, key)
}

func (r *sourceReconciler) Delete(logger logger.LogContext, obj resources.Object) reconcile.Status {
	failed := false
	logger.Infof("certificate source is deleting -> delete certificate")
	for _, s := range r.Slaves().GetByOwner(obj) {
		firstDNSName := certutils.Certificate(s).SafeFirstDNSName()
		logger.Infof("delete certificate %s(%s)", s.ObjectName(), firstDNSName)
		err := s.Delete()
		if err != nil && !errors.IsNotFound(err) {
			logger.Warnf("cannot delete certificate %s for %s: %s", s.ObjectName(), firstDNSName, err)
			failed = true
		}
	}
	if failed {
		return reconcile.Delay(logger, nil)
	}

	status := r.source.Delete(logger, obj)
	if status.IsSucceeded() {
		status = r.NestedReconciler.Delete(logger, obj)
		if status.IsSucceeded() {
			err := r.RemoveFinalizer(obj)
			if err != nil {
				return reconcile.Delay(logger, err)
			}
		}
	}

	return status
}

////////////////////////////////////////////////////////////////////////////////

func (r *sourceReconciler) createEntryFor(logger logger.LogContext, obj resources.Object, info CertInfo, feedback CertFeedback) error {
	cert := &api.Certificate{}
	cert.GenerateName = strings.ToLower(r.nameprefix + obj.GetName() + "-" + obj.GroupKind().Kind + "-")
	resources.SetAnnotation(cert, AnnotForwardOwnerRefs, "true")
	if r.targetclass != "" {
		resources.SetAnnotation(cert, AnnotClass, r.targetclass)
	}
	if len(info.Domains) > 0 {
		if len(info.Domains[0]) <= 64 {
			cert.Spec.CommonName = &info.Domains[0]
			cert.Spec.DNSNames = info.Domains[1:]
		} else {
			cert.Spec.CommonName = nil
			cert.Spec.DNSNames = info.Domains
		}
	}
	if info.IssuerName != nil {
		parts := strings.SplitN(*info.IssuerName, "/", 2)
		if len(parts) == 2 {
			cert.Spec.IssuerRef = &api.IssuerRef{Namespace: parts[0], Name: parts[1]}
		} else {
			cert.Spec.IssuerRef = &api.IssuerRef{Name: *info.IssuerName}
		}
	}
	cert.Spec.SecretRef = &core.SecretReference{
		Name:      info.SecretName.Name,
		Namespace: info.SecretName.Namespace,
	}
	if r.namespace == "" {
		cert.Namespace = obj.GetNamespace()
	} else {
		cert.Namespace = r.namespace
	}
	if info.FollowCNAME {
		cert.Spec.FollowCNAME = &info.FollowCNAME
	}
	cert.Spec.SecretLabels = info.SecretLabels
	if info.PreferredChain != "" {
		cert.Spec.PreferredChain = &info.PreferredChain
	}

	cert.Spec.PrivateKey = createPrivateKey(info.PrivateKeyAlgorithm, info.PrivateKeySize)

	for key, value := range info.Annotations {
		resources.SetAnnotation(cert, key, value)
	}

	e, _ := r.SlaveResoures()[0].Wrap(cert)

	err := r.Slaves().CreateSlave(obj, e)
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

func (r *sourceReconciler) deleteEntry(logger logger.LogContext, obj resources.Object, e resources.Object) error {
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

func (r *sourceReconciler) updateEntry(logger logger.LogContext, info CertInfo, obj resources.Object) (bool, error) {
	f := func(o resources.ObjectData) (bool, error) {
		spec := &o.(*api.Certificate).Spec
		mod := abstract.NewModificationState(obj)
		changed := resources.SetAnnotation(o, AnnotForwardOwnerRefs, "true")
		mod.Modify(changed)
		if r.targetclass == "" {
			changed = resources.RemoveAnnotation(o, AnnotClass)
		} else {
			changed = resources.SetAnnotation(o, AnnotClass, r.targetclass)
		}
		mod.Modify(changed)
		var cn *string
		var dnsNames []string
		if len(info.Domains) > 0 {
			if len(info.Domains[0]) <= 64 {
				cn = &info.Domains[0]
				dnsNames = info.Domains[1:]
			} else {
				cn = nil
				dnsNames = info.Domains
			}
		}

		mod.AssureStringPtrPtr(&spec.CommonName, cn)
		certutils.AssureStringSlice(mod, &spec.DNSNames, dnsNames)
		if info.IssuerName != nil {
			parts := strings.SplitN(*info.IssuerName, "/", 2)
			var issuerRef *api.IssuerRef
			if len(parts) == 2 {
				issuerRef = &api.IssuerRef{Namespace: parts[0], Name: parts[1]}
			} else {
				issuerRef = &api.IssuerRef{Name: *info.IssuerName}
			}
			if spec.IssuerRef == nil || spec.IssuerRef.Name != issuerRef.Name || spec.IssuerRef.Namespace != issuerRef.Namespace {
				spec.IssuerRef = issuerRef
				mod.Modify(true)
			}
		} else {
			if spec.IssuerRef != nil {
				spec.IssuerRef = nil
				mod.Modify(true)
			}
		}
		if !reflect.DeepEqual(spec.SecretLabels, info.SecretLabels) {
			spec.SecretLabels = info.SecretLabels
			mod.Modify(true)
		}
		oldFollow := spec.FollowCNAME != nil && *spec.FollowCNAME
		if info.FollowCNAME != oldFollow {
			if info.FollowCNAME {
				spec.FollowCNAME = &info.FollowCNAME
			} else {
				spec.FollowCNAME = nil
			}
			mod.Modify(true)
		}
		oldPreferredChain := ""
		if spec.PreferredChain != nil {
			oldPreferredChain = *spec.PreferredChain
		}
		if info.PreferredChain != oldPreferredChain {
			if info.PreferredChain != "" {
				spec.PreferredChain = &info.PreferredChain
			} else {
				spec.PreferredChain = nil
			}
			mod.Modify(true)
		}

		newPrivateKey := createPrivateKey(info.PrivateKeyAlgorithm, info.PrivateKeySize)
		if !reflect.DeepEqual(spec.PrivateKey, newPrivateKey) {
			spec.PrivateKey = newPrivateKey
			mod.Modify(true)
		}

		for key, value := range info.Annotations {
			if resources.SetAnnotation(o, key, value) {
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

func createPrivateKey(algorithm string, size api.PrivateKeySize) *api.CertificatePrivateKey {
	if algorithm == "" && size == 0 {
		return nil
	}
	obj := &api.CertificatePrivateKey{}
	if algorithm != "" {
		obj.Algorithm = ptr.To(api.PrivateKeyAlgorithm(algorithm))
	}
	if size != 0 {
		obj.Size = ptr.To(size)
	}
	return obj
}

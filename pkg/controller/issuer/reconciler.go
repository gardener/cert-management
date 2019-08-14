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

package issuer

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/cluster"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/cert/legobridge"
	ctrl "github.com/gardener/cert-management/pkg/controller"
)

func IssuerReconciler(c controller.Interface) (reconcile.Interface, error) {
	defaultCluster := c.GetCluster(ctrl.DefaultCluster)
	issuerResources, err := defaultCluster.Resources().GetByExample(&api.Issuer{})
	if err != nil {
		return nil, err
	}
	return &issuerReconciler{
		Interface:       c,
		issuerResources: issuerResources,
		issuerCluster:   defaultCluster,
		secrets:         NewReferencedSecrets(),
	}, nil
}

type issuerReconciler struct {
	controller.Interface
	reconcile.DefaultReconciler
	issuerCluster   cluster.Interface
	issuerResources resources.Interface
	secrets         *ReferencedSecrets
}

func (r *issuerReconciler) Reconcile(logger logger.LogContext, obj resources.Object) reconcile.Status {
	switch {
	case obj.IsA(&api.Issuer{}):
		return r.reconcileIssuer(logger, obj)
	case obj.IsA(&corev1.Secret{}):
		return r.reconcileSecret(logger, obj)
	}
	return reconcile.Succeeded(logger)
}

func (r *issuerReconciler) Deleted(logger logger.LogContext, objKey resources.ClusterObjectKey) reconcile.Status {
	removed := r.secrets.RemoveIssuer(objKey.ObjectName())
	if removed {
		return reconcile.Succeeded(logger)
	}

	// reconcile issuers for secret
	return r.reconcileSecretByObjectName(logger, objKey.ObjectName())
}

func (r *issuerReconciler) reconcileIssuer(logger logger.LogContext, obj resources.Object) reconcile.Status {
	logger.Infof("reconciling")
	issuer, ok := obj.Data().(*api.Issuer)
	if !ok {
		return failedNoType(logger, obj, api.STATE_ERROR, fmt.Errorf("casting to issuer failed"))
	}

	acme := issuer.Spec.ACME
	if acme == nil {
		return failedNoType(logger, obj, api.STATE_ERROR, fmt.Errorf("missing ACME spec"))
	}

	if acme.Email == "" {
		return failedAcme(logger, obj, api.STATE_ERROR, fmt.Errorf("missing email in ACME spec"))
	}
	if acme.Server == "" {
		return failedAcme(logger, obj, api.STATE_ERROR, fmt.Errorf("missing server in ACME spec"))
	}

	defer r.secrets.RememberIssuerSecret(issuer)

	var secret *corev1.Secret
	var err error
	if acme.PrivateKeySecretRef != nil {
		secret, err = r.readIssuerSecret(acme.PrivateKeySecretRef)
		if err != nil {
			return failedAcme(logger, obj, api.STATE_ERROR, fmt.Errorf("loading issuer secret failed with %s", err.Error()))
		}
	}
	if secret != nil && legobridge.SecretDataHasRegistration(secret.Data) {
		user, err := legobridge.RegistrationUserFromSecretData(secret.Data)
		if err != nil {
			return failedAcme(logger, obj, api.STATE_ERROR, fmt.Errorf("extracting registration user from secret failed with %s", err.Error()))
		}
		if user.Email != acme.Email {
			return failedAcme(logger, obj, api.STATE_ERROR, fmt.Errorf("email of registration user from secret does not match %s != %s", user.Email, acme.Email))
		}
		return succeeded(logger, obj, nil)
	} else if secret != nil || acme.AutoRegistration {
		var secretData map[string][]byte
		if secret != nil {
			secretData = secret.Data
		}
		user, err := legobridge.NewRegistrationUserFromEmail(acme.Email, acme.Server, secretData)
		if err != nil {
			return failedAcme(logger, obj, api.STATE_ERROR, fmt.Errorf("creating registration user failed with %s", err.Error()))
		}

		err = r.writeIssuerSecret(issuer, user, secret)
		if err != nil {
			return failedAcme(logger, obj, api.STATE_ERROR, fmt.Errorf("writing issuer secret failed with %s", err.Error()))
		}

		issuer.Status.State = api.STATE_READY
		issuer.Status.Message = nil
		newObj, err := r.issuerResources.Update(issuer)
		if err != nil {
			return failedAcme(logger, obj, api.STATE_ERROR, fmt.Errorf("updating resource failed with %s", err.Error()))
		}

		return succeeded(logger, newObj, nil)
	} else {
		return failedAcme(logger, obj, api.STATE_ERROR, fmt.Errorf("neither `SecretRef` or `AutoRegistration: true` provided"))
	}
}

func (r *issuerReconciler) reconcileSecret(logger logger.LogContext, obj resources.Object) reconcile.Status {
	return r.reconcileSecretByObjectName(logger, obj.ObjectName())
}

func (r *issuerReconciler) reconcileSecretByObjectName(logger logger.LogContext, objName resources.ObjectName) reconcile.Status {
	issuers := r.secrets.IssuerNamesFor(objName)
	if issuers != nil {
		groupKind := api.Kind(api.IssuerKind)
		clusterId := r.GetCluster(ctrl.DefaultCluster).GetId()
		for issuerName := range issuers {
			key := resources.NewClusterKey(clusterId, groupKind, issuerName.Namespace(), issuerName.Name())
			_ = r.EnqueueKey(key)
		}
	}
	return reconcile.Succeeded(logger)
}

func (r *issuerReconciler) writeIssuerSecret(issuer *api.Issuer, reguser *legobridge.RegistrationUser, secret *corev1.Secret) error {
	var err error
	if secret == nil {
		secret = &corev1.Secret{}
		secret.SetGenerateName(issuer.GetName() + "-")
		if issuer.GetNamespace() != "" {
			secret.SetNamespace(issuer.GetNamespace())
		} else {
			secret.SetNamespace("default")
		}
		secret.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: api.Version, Kind: api.IssuerKind, Name: issuer.Name, UID: issuer.GetUID()}})
		secret.Data, err = reguser.ToSecretData()
		if err != nil {
			return err
		}

		obj, err := r.issuerCluster.Resources().CreateOrUpdateObject(secret)
		if err != nil {
			return fmt.Errorf("creating/updating issuer secret failed with %s", err.Error())
		}

		issuer.Spec.ACME.PrivateKeySecretRef = &corev1.SecretReference{Name: obj.GetName(), Namespace: secret.GetNamespace()}
	} else {
		secret.Data, err = reguser.ToSecretData()
		if err != nil {
			return err
		}
		obj, err := r.issuerCluster.Resources().Wrap(secret)
		if err != nil {
			return fmt.Errorf("wrapping issuer secret failed with %s", err.Error())
		}
		err = obj.Update()
		if err != nil {
			return fmt.Errorf("updating issuer secret failed with %s", err.Error())
		}
	}

	return nil
}

func (r *issuerReconciler) readIssuerSecret(ref *corev1.SecretReference) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	itf, err := r.issuerCluster.Resources().GetByExample(secret)
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

func prepareUpdateStatus(obj resources.Object, state string, itype *string, msg *string) (*resources.ModificationState, *api.IssuerStatus) {
	crt := obj.Data().(*api.Issuer)
	status := &crt.Status

	mod := resources.NewModificationState(obj)
	mod.AssureStringPtrPtr(&status.Message, msg)
	mod.AssureStringPtrPtr(&status.Type, itype)
	mod.AssureStringValue(&status.State, state)
	mod.AssureInt64Value(&status.ObservedGeneration, obj.GetGeneration())

	return mod, status
}

func updateStatus(mod *resources.ModificationState) {
	err := mod.UpdateStatus()
	if err != nil {
		logger.Warnf("updating status failed with: %s", err)
	}
}

func failedNoType(logger logger.LogContext, obj resources.Object, state string, err error) reconcile.Status {
	return failed(logger, obj, state, nil, err)

}

func failedAcme(logger logger.LogContext, obj resources.Object, state string, err error) reconcile.Status {
	itype := ACMEType
	return failed(logger, obj, state, &itype, err)
}

func failed(logger logger.LogContext, obj resources.Object, state string, itype *string, err error) reconcile.Status {
	msg := err.Error()

	mod, _ := prepareUpdateStatus(obj, state, itype, &msg)
	updateStatus(mod)

	return reconcile.Failed(logger, err)
}

func succeeded(logger logger.LogContext, obj resources.Object, msg *string) reconcile.Status {
	itype := ACMEType
	mod, _ := prepareUpdateStatus(obj, api.STATE_READY, &itype, msg)
	updateStatus(mod)

	return reconcile.Succeeded(logger)
}

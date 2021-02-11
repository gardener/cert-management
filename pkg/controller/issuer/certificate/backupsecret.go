/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package certificate

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/gardener/controller-manager-library/pkg/resources"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/cert/legobridge"
	"github.com/gardener/cert-management/pkg/cert/utils"
)

// BackupSecret creates a backup of a certificate secret if it is not already existing.
// Returns the secret reference to the backup.
// All ACME certificates have a backup in the kube-system namespace to allow revoking them
// even if they are already renewed
func BackupSecret(res resources.Interface, secret *corev1.Secret, hashKey string,
	issuerInfo utils.IssuerInfo) (ref *api.CertificateSecretRef, created bool, err error) {

	if issuerInfo.IssuerType() != utils.IssuerTypeACME {
		return
	}

	cert, err := legobridge.DecodeCertificateFromSecretData(secret.Data)
	if err != nil {
		return
	}
	if cert.SerialNumber == nil {
		err = fmt.Errorf("missing serial number")
		return
	}
	sn := SerialNumberToString(cert.SerialNumber, true)
	list, err := res.Namespace(metav1.NamespaceSystem).List(metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s,%s=%s", LabelCertificateSerialNumber, sn, LabelCertificateHashKey, hashKey),
	})
	if err != nil {
		return
	}
	if len(list) > 0 {
		return &api.CertificateSecretRef{
			SecretReference: corev1.SecretReference{
				Name:      list[0].GetName(),
				Namespace: list[0].GetNamespace(),
			},
			SerialNumber: sn,
		}, false, nil
	}

	backupSecret := &corev1.Secret{}
	backupSecret.GenerateName = fmt.Sprintf("cert-backup-%s-%s-", issuerInfo.Name(), sn[len(sn)-8:])
	backupSecret.Namespace = metav1.NamespaceSystem
	backupSecret.Data = secret.Data
	resources.SetLabel(backupSecret, LabelCertificateHashKey, hashKey)
	resources.SetLabel(backupSecret, LabelCertificateKey, "true")
	resources.SetLabel(backupSecret, LabelCertificateSerialNumber, sn)
	resources.SetLabel(backupSecret, LabelCertificateBackup, "true")
	if _, ok := resources.GetAnnotation(secret, AnnotationRevoked); ok {
		resources.SetAnnotation(backupSecret, AnnotationRevoked, "true")
	}
	obj, err := res.Create(backupSecret)
	if err != nil {
		return
	}

	return &api.CertificateSecretRef{
		SecretReference: corev1.SecretReference{
			Name:      obj.GetName(),
			Namespace: obj.GetNamespace(),
		},
		SerialNumber: sn,
	}, true, nil
}

// FindAllCertificateSecretsByHashLabel get all certificate secrets by the certificate hash
func FindAllCertificateSecretsByHashLabel(res resources.Interface, hashKey string) ([]resources.Object, error) {
	opts := metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", LabelCertificateHashKey, hashKey),
	}
	return res.List(opts)
}

// FindAllOldBackupSecrets finds all certificate secret backups which have not been requested after the given timestamp.
func FindAllOldBackupSecrets(res resources.Interface, hashKey string, timestamp time.Time) ([]api.CertificateSecretRef, error) {
	list, err := res.Namespace(metav1.NamespaceSystem).List(metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", LabelCertificateHashKey, hashKey),
	})
	if err != nil {
		return nil, err
	}

	refs := []api.CertificateSecretRef{}
	for _, item := range list {
		if item.GetAnnotation(AnnotationRevoked) != "" {
			continue
		}
		secret := item.Data().(*corev1.Secret)
		cert, err := legobridge.DecodeCertificateFromSecretData(secret.Data)
		if err != nil {
			// ignore invalid secrets
			continue
		}
		if !IsValidNow(cert) {
			continue
		}
		if WasRequestedBefore(cert, timestamp) {
			refs = append(refs, api.CertificateSecretRef{
				SecretReference: corev1.SecretReference{
					Name:      item.GetName(),
					Namespace: item.GetNamespace(),
				},
				SerialNumber: SerialNumberToString(cert.SerialNumber, false),
			})
		}
	}
	if len(refs) == 0 {
		return nil, fmt.Errorf("no valid secrets found older than %s", timestamp)
	}
	return refs, nil
}

// SerialNumberToString get string representation of certificate serial number
func SerialNumberToString(sn *big.Int, compact bool) string {
	if sn == nil {
		return "nil"
	}
	builder := strings.Builder{}
	for i, r := range sn.Text(16) {
		if !compact && i%2 == 0 && i != 0 {
			builder.WriteRune(':')
		}
		builder.WriteRune(r)
	}
	return builder.String()
}

// WasRequestedBefore returns true if the certificate was not requested after the given timestamp.
// This method uses the `notBefore` time of the certificate. Let's Encrypt sets the `notBefore`
// time one hour in the past of request, here it is checked if the `notBefore` time is
// more than 61 minutes in the past of the given timestamp (30 seconds are added for robustness, e.g. possible time drift)
func WasRequestedBefore(cert *x509.Certificate, timestamp time.Time) bool {
	return timestamp.After(cert.NotBefore.Add(1*time.Hour + 30*time.Second))
}

// IsValidNow returns true if the certificate is still valid
func IsValidNow(cert *x509.Certificate) bool {
	return !time.Now().After(cert.NotAfter)
}

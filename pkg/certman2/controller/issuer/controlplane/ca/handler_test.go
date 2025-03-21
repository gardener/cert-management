// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	certmanclient "github.com/gardener/cert-management/pkg/certman2/client"
	"github.com/gardener/cert-management/pkg/certman2/core"
	"github.com/gardener/cert-management/pkg/shared/legobridge"
)

var _ = Describe("Handler", func() {
	var (
		ctx = context.Background()
		log = logr.Discard()

		fakeClient      client.Client
		caIssuerHandler core.IssuerHandler
		support         *core.Support
		caIssuer        *v1alpha1.Issuer
	)

	BeforeEach(func() {
		var err error
		fakeClient = fakeclient.NewClientBuilder().WithScheme(certmanclient.ClusterScheme).WithStatusSubresource(&v1alpha1.Issuer{}).Build()
		support, err = core.NewHandlerSupport("issuer-ca", "default", 100)
		Expect(err).NotTo(HaveOccurred())
		caIssuerHandler, err = NewCAIssuerHandler(fakeClient, support, true)
		Expect(err).NotTo(HaveOccurred())

		caIssuer = &v1alpha1.Issuer{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "issuer-ca",
				Namespace: "default",
			},
			Spec: v1alpha1.IssuerSpec{
				CA: &v1alpha1.CASpec{
					PrivateKeySecretRef: &corev1.SecretReference{
						Name:      "issuer-ca-secret",
						Namespace: "default",
					},
				},
			},
		}

		err = fakeClient.Create(ctx, caIssuer)
		Expect(err).NotTo(HaveOccurred())

		certPEM, certPrivKeyPEM, err := NewSelfSignedCertInPEMFormat(x509.RSA, 2048)
		Expect(err).NotTo(HaveOccurred())
		secretData := map[string][]byte{"tls.crt": certPEM, "tls.key": certPrivKeyPEM}
		secret := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "issuer-ca-secret",
				Namespace: "default",
			},
			Data: secretData,
			Type: "kubernetes.io/tls",
		}
		err = fakeClient.Create(ctx, &secret)
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("#Reconcile", func() {
		It("should return success if there are no errors", func() {
			reconcileResult, err := caIssuerHandler.Reconcile(ctx, log, caIssuer)
			Expect(reconcileResult.IsZero()).To(BeTrue())
			Expect(err).NotTo(HaveOccurred())
			err = fakeClient.Get(ctx, client.ObjectKeyFromObject(caIssuer), caIssuer)
			Expect(err).NotTo(HaveOccurred())
			Expect(caIssuer.Status.State).To(Equal("Ready"))
			Expect(*caIssuer.Status.Type).To(Equal("ca"))
		})
		It("should return error if secret not existing", func() {
			caIssuer.Spec.CA.PrivateKeySecretRef.Name = "foo"
			reconcileResult, err := caIssuerHandler.Reconcile(ctx, log, caIssuer)
			Expect(reconcileResult.IsZero()).To(BeTrue())
			Expect(err).To(HaveOccurred())
			Expect(caIssuer.Status.State).To(Equal("Error"))
		})
	})
	Describe("#Delete", func() {
		It("should return success if there are no errors", func() {
			reconcileResult, err := caIssuerHandler.Reconcile(ctx, log, caIssuer)
			Expect(reconcileResult.IsZero()).To(BeTrue())
			Expect(err).NotTo(HaveOccurred())
			now := metav1.Now()
			caIssuer.DeletionTimestamp = &now
			reconcileResult, err = caIssuerHandler.Delete(ctx, log, caIssuer)
			Expect(reconcileResult.IsZero()).To(BeTrue())
			Expect(err).NotTo(HaveOccurred())
		})
	})
})

// TODO replace with existing method if SelfSigned certificate feature is merged: https://github.com/gardener/cert-management/pull/228
func NewSelfSignedCertInPEMFormat(algo x509.PublicKeyAlgorithm, algoSize int) ([]byte, []byte, error) {
	certPrivateKey, certPrivateKeyPEM, err := legobridge.GenerateKey(algo, algoSize)
	if err != nil {
		return nil, nil, err
	}
	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	if algo == x509.RSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "host.example.com",
		},
		DNSNames:              []string{"host2.example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
	}

	certDerBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, certPrivateKey.Public(), certPrivateKey)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDerBytes})
	return certPEM, certPrivateKeyPEM, nil
}

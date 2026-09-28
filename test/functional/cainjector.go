/*
 * SPDX-FileCopyrightText: Contributors to the Gardener project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package functional

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/cert-management/pkg/controller/cainjector"
)

const (
	caInjectorSecretName  = "test-cainjector-secret"
	caInjectorAPIService  = "v1alpha1.cainjector-test.sap.com"
	caInjectorSecretRef   = "default/" + caInjectorSecretName
	caInjectorSecretDataK = "ca.crt"
)

func init() {
	_ = Describe("cainjector", func() {
		// This is the end-to-end counterpart of hack/dev-test-cainjector.sh: it verifies that
		// the CA injector, as deployed in the kind cluster (RBAC + --controllers flags), injects
		// a CA bundle into an APIService via the direct-injection annotation and re-injects it
		// after the source CA is rotated. The APIService injectable and the rotation flow are not
		// covered by the envtest-based integration test in test/integration/controller/cainjector.
		It("injects and rotates the CA bundle of an APIService", func(ctx context.Context) {
			u := getConfig().Utils
			c := u.Client

			caPEM, err := makeSelfSignedCAPEM("test-ca")
			Expect(err).ShouldNot(HaveOccurred())

			By("creating the CA secret with the allow-direct-injection guard")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      caInjectorSecretName,
					Namespace: u.Namespace,
					Annotations: map[string]string{
						cainjector.AnnotationAllowDirectInjection: "true",
					},
				},
				Data: map[string][]byte{caInjectorSecretDataK: caPEM},
			}
			Expect(c.Create(ctx, secret)).To(Succeed())
			DeferCleanup(func(ctx context.Context) {
				Expect(client.IgnoreNotFound(c.Delete(ctx, secret))).To(Succeed())
			})

			By("creating the APIService referencing the CA secret")
			apiService := &apiregistrationv1.APIService{
				ObjectMeta: metav1.ObjectMeta{
					Name: caInjectorAPIService,
					Annotations: map[string]string{
						cainjector.AnnotationInjectCAFromSecret: caInjectorSecretRef,
					},
				},
				Spec: apiregistrationv1.APIServiceSpec{
					Group:                "cainjector-test.sap.com",
					GroupPriorityMinimum: 1000,
					VersionPriority:      15,
					Service: &apiregistrationv1.ServiceReference{
						Name:      "api",
						Namespace: u.Namespace,
					},
					Version: "v1alpha1",
				},
			}
			Expect(c.Create(ctx, apiService)).To(Succeed())
			DeferCleanup(func(ctx context.Context) {
				Expect(client.IgnoreNotFound(c.Delete(ctx, apiService))).To(Succeed())
			})

			By("waiting for the initial caBundle injection")
			Eventually(func(g Gomega) []byte {
				g.Expect(c.Get(ctx, client.ObjectKeyFromObject(apiService), apiService)).To(Succeed())
				return apiService.Spec.CABundle
			}).WithPolling(time.Second).WithTimeout(60 * time.Second).Should(Equal(caPEM))
			initialBundle := apiService.Spec.CABundle

			By("rotating the CA in the source secret")
			rotatedPEM, err := makeSelfSignedCAPEM("rotated-ca")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(rotatedPEM).ShouldNot(Equal(initialBundle))

			Expect(c.Get(ctx, client.ObjectKeyFromObject(secret), secret)).To(Succeed())
			secret.Data[caInjectorSecretDataK] = rotatedPEM
			Expect(c.Update(ctx, secret)).To(Succeed())

			By("waiting for the caBundle to reflect the rotated CA")
			Eventually(func(g Gomega) []byte {
				g.Expect(c.Get(ctx, client.ObjectKeyFromObject(apiService), apiService)).To(Succeed())
				return apiService.Spec.CABundle
			}).WithPolling(time.Second).WithTimeout(60 * time.Second).Should(Equal(rotatedPEM))
		}, SpecTimeout(180*time.Second))
	})
}

// makeSelfSignedCAPEM generates a short-lived self-signed CA certificate and returns it
// PEM-encoded, mirroring the `openssl req -x509` calls in hack/dev-test-cainjector.sh.
func makeSelfSignedCAPEM(commonName string) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

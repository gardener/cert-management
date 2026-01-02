// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package source_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"time"

	. "github.com/gardener/gardener/pkg/utils/test/matchers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"golang.org/x/crypto/acme"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	componentbaseconfig "k8s.io/component-base/config"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	controllerconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/certman2/apis/config"
	issuercontrolplane "github.com/gardener/cert-management/pkg/certman2/controller/issuer/controlplane"
	"github.com/gardener/cert-management/pkg/certman2/core"
	"github.com/gardener/cert-management/pkg/shared/legobridge"
)

var (
	acmeServerURL string = "https://acme-staging-v02.api.letsencrypt.org/directory"
	acmeEmail     string = "some.user@mydomain.com"
)

var _ = Describe("Issuer controller tests", func() {
	var (
		testRunID     string
		testNamespace *corev1.Namespace
	)

	BeforeEach(func() {
		By("Create test Namespace")
		testNamespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "issuer-",
			},
		}
		Expect(testClient.Create(ctx, testNamespace)).To(Succeed())
		log.Info("Created Namespace for test", "namespaceName", testNamespace.Name)
		testRunID = testNamespace.Name

		DeferCleanup(func() {
			By("Delete test Namespace")
			Expect(testClient.Delete(ctx, testNamespace)).To(Or(Succeed(), BeNotFoundError()))
		})

		By("Setup manager")
		httpClient, err := rest.HTTPClientFor(restConfig)
		Expect(err).NotTo(HaveOccurred())
		mapper, err := apiutil.NewDynamicRESTMapper(restConfig, httpClient)
		Expect(err).NotTo(HaveOccurred())

		mgr, err := manager.New(restConfig, manager.Options{
			Scheme:  scheme,
			Metrics: metricsserver.Options{BindAddress: "0"},
			Cache: cache.Options{
				Mapper: mapper,
				ByObject: map[client.Object]cache.ByObject{
					&apiextensionsv1.CustomResourceDefinition{}: {},
					&v1alpha1.Issuer{}: {
						Namespaces: map[string]cache.Config{testRunID: {}},
					},
				},
			},
			Controller: controllerconfig.Controller{
				SkipNameValidation: ptr.To(true),
			},
		})
		Expect(err).NotTo(HaveOccurred())

		cfg := &config.CertManagerConfiguration{
			LeaderElection: componentbaseconfig.LeaderElectionConfiguration{
				LeaderElect: false,
			},
			Class:    "class-" + testRunID,
			LogLevel: "debug",
			Controllers: config.ControllerConfiguration{
				Issuer: config.IssuerControllerConfig{
					Namespace: testNamespace.Name,
				},
			},
		}

		By("Register issuer controllers")
		issuerReconciler := &issuercontrolplane.Reconciler{
			Config: *cfg,
		}
		Expect(issuerReconciler.AddToManager(mgr, mgr)).To(Succeed())

		By("Start manager")
		mgrContext, mgrCancel := context.WithCancel(ctx)

		go func() {
			defer GinkgoRecover()
			Expect(mgr.Start(mgrContext)).To(Succeed())
		}()

		DeferCleanup(func() {
			By("Stop manager")
			mgrCancel()
		})
	})

	Context("ACME Issuer with autoregistration true", func() {
		It("Deleting ACME issuer with autoregistration true should delete corresponding secret", func() {
			acmeIssuer := &v1alpha1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "acme-issuer",
					Namespace: testRunID,
					Annotations: map[string]string{
						"cert.gardener.cloud/class": "class-" + testRunID,
					},
				},
				Spec: v1alpha1.IssuerSpec{
					ACME: &v1alpha1.ACMESpec{
						Server:           acmeServerURL,
						Email:            acmeEmail,
						AutoRegistration: true,
					},
				},
			}
			Expect(testClient.Create(ctx, acmeIssuer)).To(Succeed())

			By("Wait for issuer")
			var secretName string
			Eventually(func(g Gomega) {
				err := testClient.Get(ctx, client.ObjectKeyFromObject(acmeIssuer), acmeIssuer)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(acmeIssuer.Status.State).To(Equal("Ready"))
				secretName = acmeIssuer.Spec.ACME.PrivateKeySecretRef.Name
			}).Should(Succeed())
			Expect(secretName).NotTo(BeEmpty())
			secret := &corev1.Secret{}
			err := testClient.Get(ctx, client.ObjectKey{Namespace: testRunID, Name: secretName}, secret)
			Expect(err).NotTo(HaveOccurred())
			// we just check if secret has correct owner reference since garbage collection does not work in envtest environment
			Expect(secret.OwnerReferences).To(ContainElement(metav1.OwnerReference{
				APIVersion: "cert.gardener.cloud/v1alpha1",
				Kind:       "Issuer",
				Name:       acmeIssuer.Name,
				UID:        acmeIssuer.UID,
			}))
			Expect(testClient.Delete(ctx, acmeIssuer)).To(Succeed())
			Expect(testClient.Delete(ctx, secret)).To(Succeed())
		})
	})

	Context("ACME Issuer", func() {
		It("Changing secret should reconcile issuer and update secretHash of issuer status", func() {
			acmeIssuer := &v1alpha1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "acme-issuer",
					Namespace: testRunID,
					Annotations: map[string]string{
						"cert.gardener.cloud/class": "class-" + testRunID,
					},
				},
				Spec: v1alpha1.IssuerSpec{
					ACME: &v1alpha1.ACMESpec{
						Server:           acmeServerURL,
						Email:            acmeEmail,
						AutoRegistration: true,
					},
				},
			}
			Expect(testClient.Create(ctx, acmeIssuer)).To(Succeed())
			By("Wait for issuer")
			Eventually(func(g Gomega) {
				err := testClient.Get(ctx, client.ObjectKeyFromObject(acmeIssuer), acmeIssuer)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(acmeIssuer.Status.State).To(Equal("Ready"))
			}).Should(Succeed())
			registration, err := core.WrapRegistrationFromResource(acmeIssuer.Status.ACME.Raw)
			Expect(err).NotTo(HaveOccurred())
			secretHashBefore := registration.SecretHash

			By("Update secret")
			secretName := acmeIssuer.Spec.ACME.PrivateKeySecretRef.Name
			Expect(secretName).NotTo(BeEmpty())
			secret := &corev1.Secret{}
			err = testClient.Get(ctx, client.ObjectKey{Namespace: testRunID, Name: secretName}, secret)
			Expect(err).NotTo(HaveOccurred())
			oldPrivateKeyPEM := secret.Data["privateKey"]
			_, newPrivateKeyPEM, err := legobridge.GenerateKey(x509.ECDSA, 256, false)
			Expect(err).NotTo(HaveOccurred())
			_, err = changeKeyInBackend(ctx, oldPrivateKeyPEM, newPrivateKeyPEM)
			Expect(err).NotTo(HaveOccurred())
			secret.Data["privateKey"] = newPrivateKeyPEM
			err = testClient.Update(ctx, secret)
			Expect(err).NotTo(HaveOccurred())

			By("Check if issuer has a new secret hash")
			Eventually(func(g Gomega) {
				err = testClient.Get(ctx, client.ObjectKeyFromObject(acmeIssuer), acmeIssuer)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(core.IsSameExistingRegistration(acmeIssuer.Status.ACME, *secretHashBefore)).To(BeFalse())
			}, time.Second*3, time.Second).Should(Succeed())
			Expect(testClient.Delete(ctx, acmeIssuer)).To(Succeed())
			Expect(testClient.Delete(ctx, secret)).To(Succeed())
		})

		It("should have validation errors for issuer secret with invalid secret", func() {
			By("Create ACME issuer")
			acmeIssuer := &v1alpha1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "acme-issuer",
					Namespace: testRunID,
					Annotations: map[string]string{
						"cert.gardener.cloud/class": "class-" + testRunID,
					},
				},
				Spec: v1alpha1.IssuerSpec{
					ACME: &v1alpha1.ACMESpec{
						Server:           acmeServerURL,
						Email:            acmeEmail,
						AutoRegistration: true,
						PrivateKeySecretRef: &corev1.SecretReference{
							Name:      "invalid-secret",
							Namespace: testRunID,
						},
					},
				},
			}
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      acmeIssuer.Spec.ACME.PrivateKeySecretRef.Name,
					Namespace: testRunID,
				},
				Data: map[string][]byte{
					legobridge.KeyPrivateKey: []byte("dummy"),
				},
			}
			Expect(testClient.Create(ctx, secret)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, secret)).To(Succeed())
			})
			Expect(testClient.Create(ctx, acmeIssuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, acmeIssuer)).To(Succeed())
			})

			By("Wait for issuer to have state error because of invalid private key encoding")
			Eventually(func(g Gomega) v1alpha1.IssuerStatus {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(acmeIssuer), acmeIssuer)).To(Succeed())
				return acmeIssuer.Status
			}).Should(MatchFields(IgnoreExtras, Fields{
				"State":   Equal("Error"),
				"Message": PointTo(Equal(fmt.Sprintf("validation of data keys failed for secret %s: value for key `privateKey` is invalid: decoding pem block for private key failed", client.ObjectKeyFromObject(secret)))),
			}))

			By("Wait for issuer to auto-registrate")
			Expect(testClient.Delete(ctx, secret)).To(Succeed())
			Eventually(func(g Gomega) string {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(acmeIssuer), acmeIssuer)).To(Succeed())
				return acmeIssuer.Status.State
			}).Should(Equal("Ready"))

			By("Wait for issuer to have validation error because of invalid key")
			Expect(testClient.Get(ctx, client.ObjectKeyFromObject(secret), secret)).To(Succeed())
			secret.Data["invalid-key"] = []byte("this-is-not-a-data-key")
			secret.Data[legobridge.ObsoleteKeyEmail] = []byte("dummy@example.com") // This key is obsolete but still allowed for backward compatibility
			Expect(testClient.Update(ctx, secret)).To(Succeed())
			Eventually(func(g Gomega) v1alpha1.IssuerStatus {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(acmeIssuer), acmeIssuer)).To(Succeed())
				return acmeIssuer.Status
			}).Should(MatchFields(IgnoreExtras, Fields{
				"State":   Equal("Error"),
				"Message": PointTo(Equal(fmt.Sprintf("validation of data keys failed for secret %s: invalid secret data keys: `invalid-key`", client.ObjectKeyFromObject(secret)))),
			}))
		})

		It("should have validation errors for issuer secret with invalid EAB secret", func() {
			By("Create ACME issuer")
			acmeIssuer := &v1alpha1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "acme-issuer",
					Namespace: testRunID,
					Annotations: map[string]string{
						"cert.gardener.cloud/class": "class-" + testRunID,
					},
				},
				Spec: v1alpha1.IssuerSpec{
					ACME: &v1alpha1.ACMESpec{
						Server:           acmeServerURL,
						Email:            acmeEmail,
						AutoRegistration: true,
						ExternalAccountBinding: &v1alpha1.ACMEExternalAccountBinding{
							KeyID: "test",
							KeySecretRef: &corev1.SecretReference{
								Name:      "invalid-secret",
								Namespace: testRunID,
							},
						},
					},
				},
			}
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      acmeIssuer.Spec.ACME.ExternalAccountBinding.KeySecretRef.Name,
					Namespace: acmeIssuer.Spec.ACME.ExternalAccountBinding.KeySecretRef.Namespace,
				},
				Data: map[string][]byte{
					legobridge.KeyHmacKey: []byte("dummy"),
					"invalid-key":         []byte("this-is-not-a-data-key"),
				},
			}
			Expect(testClient.Create(ctx, secret)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, secret)).To(Succeed())
			})
			Expect(testClient.Create(ctx, acmeIssuer)).To(Succeed())
			DeferCleanup(func() {
				Expect(testClient.Delete(ctx, acmeIssuer)).To(Succeed())
			})

			By("Wait for issuer to have state error because of invalid data key")
			Eventually(func(g Gomega) v1alpha1.IssuerStatus {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(acmeIssuer), acmeIssuer)).To(Succeed())
				return acmeIssuer.Status
			}).Should(MatchFields(IgnoreExtras, Fields{
				"State":   Equal("Error"),
				"Message": PointTo(Equal(fmt.Sprintf("loading EAB secret failed: EAB secret %s contains unexpected keys: invalid-key", client.ObjectKeyFromObject(secret)))),
			}))

			By("Wait for issuer to have state error because of invalid key value (not base64 encoded)")
			Expect(testClient.Get(ctx, client.ObjectKeyFromObject(secret), secret)).To(Succeed())
			delete(secret.Data, "invalid-key")
			Expect(testClient.Update(ctx, secret)).To(Succeed())
			Eventually(func(g Gomega) v1alpha1.IssuerStatus {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(acmeIssuer), acmeIssuer)).To(Succeed())
				return acmeIssuer.Status
			}).Should(MatchFields(IgnoreExtras, Fields{
				"State":   Equal("Error"),
				"Message": PointTo(HavePrefix("creating registration user failed: acme: could not decode hmac key: illegal base64 data")),
			}))

			By("Wait for issuer to have state error because of key value too short")
			Expect(testClient.Get(ctx, client.ObjectKeyFromObject(secret), secret)).To(Succeed())
			secret.Data[legobridge.KeyHmacKey] = []byte(base64.RawURLEncoding.EncodeToString([]byte("dummy")))
			Expect(testClient.Update(ctx, secret)).To(Succeed())
			Eventually(func(g Gomega) v1alpha1.IssuerStatus {
				g.Expect(testClient.Get(ctx, client.ObjectKeyFromObject(acmeIssuer), acmeIssuer)).To(Succeed())
				return acmeIssuer.Status
			}).Should(MatchFields(IgnoreExtras, Fields{
				"State":   Equal("Error"),
				"Message": PointTo(HavePrefix("creating registration user failed: acme: error signing eab content: failed to External Account Binding sign content: go-jose/go-jose: invalid key size for algorithm")),
			}))
		})

	})
})

func changeKeyInBackend(ctx context.Context, oldKeyPEM []byte, newKeyPEM []byte) (acme.KeyID, error) {
	oldKey, err := decodeAndParseKey(oldKeyPEM)
	if err != nil {
		return "", fmt.Errorf("decoding/parsing old key failed: %s", err)
	}
	newKey, err := decodeAndParseKey(newKeyPEM)
	if err != nil {
		return "", fmt.Errorf("decoding/parsing new key failed: %s", err)
	}

	client := createClient(oldKey, acmeServerURL)
	// explicit timeout to avoid endless retry for status code 501 (not implemented) on smallstep certificates server
	callCtx, cancel := context.WithTimeout(ctx, client.HTTPClient.Timeout+10*time.Second)
	defer cancel()
	if err := client.AccountKeyRollover(callCtx, newKey); err != nil {
		return "", fmt.Errorf("keychange request on server %s failed: %w", acmeServerURL, err)
	}
	return client.KID, nil
}

func createHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 2 * time.Minute,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}
}

func createClient(key crypto.Signer, serverURL string) acme.Client {
	return acme.Client{
		Key:          key,
		HTTPClient:   createHTTPClient(),
		DirectoryURL: serverURL,
		RetryBackoff: nil,
	}
}

func decodeAndParseKey(pemBlock []byte) (crypto.Signer, error) {
	keyDERBlock, _ := pem.Decode(pemBlock)
	return x509.ParseECPrivateKey(keyDERBlock.Bytes)
}

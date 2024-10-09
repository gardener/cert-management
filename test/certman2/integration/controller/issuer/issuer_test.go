// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package source_test

import (
	"context"
	"github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/certman2/apis/config"
	issuercontrolplane "github.com/gardener/cert-management/pkg/certman2/controller/issuer/controlplane"
	. "github.com/gardener/gardener/pkg/utils/test/matchers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	componentbaseconfig "k8s.io/component-base/config"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
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
		})
		Expect(err).NotTo(HaveOccurred())

		cfg := &config.CertManagerConfiguration{
			LeaderElection: componentbaseconfig.LeaderElectionConfiguration{
				LeaderElect: false,
			},
			Class:    testRunID,
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

	Context("Issuer controller tests", func() {
		It("should successfully create an acme issuer", func() {
			acmeIssuer := &v1alpha1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "acme-issuer",
					Namespace: testRunID,
				},
				Spec: v1alpha1.IssuerSpec{
					ACME: &v1alpha1.ACMESpec{
						Server: "https://acme-staging-v02.api.letsencrypt.org/directory",
						// Email:  "some.user@mydomain.com",
						AutoRegistration: true,
					},
				},
			}
			Expect(testClient.Create(ctx, acmeIssuer)).To(Succeed())
			By("Wait for issuer")
			Eventually(func(g Gomega) {
				err := testClient.Get(ctx, client.ObjectKeyFromObject(acmeIssuer), acmeIssuer)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(acmeIssuer.Status.State).To(Equal("ErrorX"))
			}).Should(Succeed())
		})
	})
})

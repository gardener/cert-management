// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package source_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/gardener/gardener/pkg/logger"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	certmanclient "github.com/gardener/cert-management/pkg/certman2/client"
)

func TestSourceController(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Test Integration Source Controller Suite")
}

const testID = "source-controller-test"

var (
	ctx = context.Background()
	log logr.Logger

	restConfig *rest.Config
	testEnv    *envtest.Environment
	testClient client.Client
	mgrClient  client.Client

	scheme *runtime.Scheme
)

var _ = BeforeSuite(func() {
	// a lot of CPU-intensive stuff is happening in this test, so to
	// prevent flakes we have to increase the timeout here manually
	SetDefaultEventuallyTimeout(5 * time.Second)

	logf.SetLogger(logger.MustNewZapLogger(logger.DebugLevel, logger.FormatJSON, zap.WriteTo(GinkgoWriter)))
	log = logf.Log.WithName(testID)

	By("Start test environment")
	testEnv = &envtest.Environment{
		CRDInstallOptions: envtest.CRDInstallOptions{
			Paths: []string{
				filepath.Join("..", "..", "..", "..", "..", "pkg", "certman2", "apis", "cert", "crd-cert.gardener.cloud_certificates.yaml"),
				filepath.Join("testdata", "crd-gateways.networking.istio.io_v1.yaml"),
				filepath.Join("testdata", "crd-virtualservices.networking.istio.io_v1.yaml"),
				filepath.Join("testdata", "crd-gateways.gateway.networking.k8s.io_v1.yaml"),
				filepath.Join("testdata", "crd-httproutes.gateway.networking.k8s.io_v1.yaml"),
			},
		},
		ErrorIfCRDPathMissing: true,
	}

	var err error
	restConfig, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(restConfig).NotTo(BeNil())

	DeferCleanup(func() {
		By("Stop test environment")
		Expect(testEnv.Stop()).To(Succeed())
	})

	By("Create test client")
	scheme = certmanclient.ClusterScheme

	testClient, err = client.New(restConfig, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())
})

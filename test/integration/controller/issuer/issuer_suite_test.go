// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package issuer_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	certclient "github.com/gardener/cert-management/pkg/cert/client"
	ctrl "github.com/gardener/cert-management/pkg/controller"
	_ "github.com/gardener/cert-management/pkg/controller/issuer"

	"github.com/gardener/controller-manager-library/pkg/controllermanager"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/cluster"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/mappings"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/controller-manager-library/pkg/utils"
	"github.com/gardener/gardener/pkg/logger"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubernetesscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func TestIssuerController(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Test Integration Issuer Controller Suite")
}

const testID = "issuer-controller-test"

var (
	ctx context.Context
	log logr.Logger

	restConfig     *rest.Config
	testEnv        *envtest.Environment
	testClient     client.Client
	kubeconfigFile string

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
				filepath.Join("..", "..", "..", "..", "pkg", "apis", "cert", "crds", "cert.gardener.cloud_certificaterevocations.yaml"),
				filepath.Join("..", "..", "..", "..", "pkg", "apis", "cert", "crds", "cert.gardener.cloud_certificates.yaml"),
				filepath.Join("..", "..", "..", "..", "pkg", "apis", "cert", "crds", "cert.gardener.cloud_issuers.yaml"),
				filepath.Join("..", "..", "..", "..", "examples", "11-dns.gardener.cloud_dnsentries.yaml"),
			},
		},
		ErrorIfCRDPathMissing: true,
	}

	var err error
	restConfig, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(restConfig).NotTo(BeNil())

	kubeconfigFile = createKubeconfigFile(restConfig)
	os.Setenv("KUBECONFIG", kubeconfigFile)

	doInit()

	DeferCleanup(func() {
		By("Stop test environment")
		Expect(testEnv.Stop()).To(Succeed())
		_ = os.Remove(kubeconfigFile)
	})

	By("Create test client")
	scheme = certclient.ClusterScheme

	testClient, err = client.New(restConfig, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())
})

func createKubeconfigFile(cfg *rest.Config) string {
	template := `apiVersion: v1
kind: Config
clusters:
  - name: testenv
    cluster:
      server: '%s'
      certificate-authority-data: %s
contexts:
  - name: testenv
    context:
      cluster: testenv
      user: testuser
current-context: testenv
users:
  - name: testuser
    user:
      client-certificate-data: %s
      client-key-data: %s`

	tmpfile, err := os.CreateTemp("", "kubeconfig-integration-suite-test")
	Expect(err).NotTo(HaveOccurred())
	_, err = fmt.Fprintf(tmpfile, template, cfg.Host, base64.StdEncoding.EncodeToString(cfg.CAData),
		base64.StdEncoding.EncodeToString(cfg.CertData), base64.StdEncoding.EncodeToString(cfg.KeyData))
	Expect(err).NotTo(HaveOccurred())
	err = tmpfile.Close()
	Expect(err).NotTo(HaveOccurred())
	return tmpfile.Name()
}

func doInit() {
	cluster.Configure(
		ctrl.TargetCluster,
		"target",
		"target cluster for certificates",
	).Fallback(ctrl.SourceCluster).MustRegister()

	cluster.Configure(
		ctrl.SourceCluster,
		"source",
		"source cluster to watch for ingresses and services",
	).MustRegister()

	mappings.ForControllerGroup(ctrl.ControllerGroupCert).
		MustRegister()

	utils.Must(resources.Register(v1alpha1.SchemeBuilder))
	utils.Must(resources.Register(apiextensionsv1.SchemeBuilder))
	utils.Must(resources.Register(runtime.SchemeBuilder{kubernetesscheme.AddToScheme}))
}

func runControllerManager(ctx context.Context, args []string) {
	use := "cert-controller-manager"
	short := "integration-test"
	c := controllermanager.PrepareStart(use, short)
	def := c.Definition()
	os.Args = args
	command := controllermanager.NewCommand(ctx, use, short, short, def)
	if err := command.Execute(); err != nil {
		log.Error(err, "controllermanager command failed")
	}
}

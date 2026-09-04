// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package cainjector_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/gardener/controller-manager-library/pkg/configmain"
	"github.com/gardener/controller-manager-library/pkg/controllermanager"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/cluster"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/mappings"
	"github.com/gardener/controller-manager-library/pkg/ctxutil"
	cmllogger "github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/controller-manager-library/pkg/run"
	"github.com/gardener/controller-manager-library/pkg/utils"
	dnsapi "github.com/gardener/external-dns-management/pkg/apis/dns/v1alpha1"
	"github.com/gardener/gardener/pkg/logger"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/cobra"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubernetesscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	certclient "github.com/gardener/cert-management/pkg/cert/client"
	ctrl "github.com/gardener/cert-management/pkg/controller"
	_ "github.com/gardener/cert-management/pkg/controller/cainjector"
)

func TestCAInjectorIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CA Injector Integration Suite")
}

const testID = "cainjector-integration-test"

var (
	ctx            context.Context
	log            logr.Logger
	restConfig     *rest.Config
	testEnv        *envtest.Environment
	testClient     client.Client
	kubeconfigFile string
)

var _ = BeforeSuite(func() {
	cmllogger.SetOutput(GinkgoWriter)
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
	testClient, err = client.New(restConfig, client.Options{Scheme: certclient.ClusterScheme})
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

	tmpfile, err := os.CreateTemp("", "kubeconfig-cainjector-integration-test")
	Expect(err).NotTo(HaveOccurred())
	_, err = fmt.Fprintf(tmpfile, template, cfg.Host,
		base64.StdEncoding.EncodeToString(cfg.CAData),
		base64.StdEncoding.EncodeToString(cfg.CertData),
		base64.StdEncoding.EncodeToString(cfg.KeyData))
	Expect(err).NotTo(HaveOccurred())
	Expect(tmpfile.Close()).To(Succeed())
	return tmpfile.Name()
}

func doInit() {
	cluster.Configure(
		ctrl.TargetCluster,
		"target",
		"target cluster",
	).Fallback(ctrl.SourceCluster).MustRegister()

	cluster.Configure(
		ctrl.SourceCluster,
		"source",
		"source cluster",
	).MustRegister()

	mappings.ForControllerGroup(ctrl.ControllerGroupCAInjector).
		MustRegister()

	utils.Must(resources.Register(corev1.SchemeBuilder))
	utils.Must(resources.Register(v1alpha1.SchemeBuilder))
	utils.Must(resources.Register(apiextensionsv1.SchemeBuilder))
	utils.Must(resources.Register(admissionregistrationv1.SchemeBuilder))
	utils.Must(resources.Register(dnsapi.SchemeBuilder))
	utils.Must(resources.Register(runtime.SchemeBuilder{kubernetesscheme.AddToScheme}))
}

func newContext() {
	ctx0 := ctxutil.CancelContext(ctxutil.WaitGroupContext(context.Background(), "main"))
	ctx = ctxutil.TickContext(ctx0, controllermanager.DeletionActivity)
}

func startManager() {
	newContext()
	go func() {
		defer GinkgoRecover()
		args := []string{
			"--kubeconfig", kubeconfigFile,
			"--controllers", "cainjector-mutatingwebhook,cainjector-validatingwebhook,cainjector-crd",
			"--omit-lease",
		}
		if err := runControllerManager(ctx, args); err != nil {
			log.Error(err, "controller manager stopped with error")
		}
	}()
}

func stopManager() {
	if ctx != nil {
		ctxutil.Cancel(ctx)
	}
}

func runControllerManager(ctx context.Context, args []string) error {
	use := "cert-controller-manager"
	short := "cainjector-integration-test"
	c := controllermanager.PrepareStart(use, short)
	def := c.Definition()

	ctx, cfg := configmain.WithConfig(ctx, nil)
	def.ExtendConfig(cfg)
	controllermanager.DisableOptionSettingsLogging = true

	cmd := &cobra.Command{Use: use, Short: short}
	cfg.AddToCommand(cmd)
	cmd.SetArgs(args)
	cmd.RunE = func(_ *cobra.Command, _ []string) error {
		return run.Run(ctx, func() error {
			cm, err := controllermanager.NewControllerManager(ctx, def)
			if err != nil {
				return err
			}
			return cm.Run()
		})
	}
	return cmd.Execute()
}

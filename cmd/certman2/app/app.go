package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	goruntime "runtime"
	"strconv"
	"time"

	cmdutils "github.com/gardener/gardener/cmd/utils"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/controllerutils/routes"
	gardenerhealthz "github.com/gardener/gardener/pkg/healthz"
	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	vpaautoscalingv1 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1"
	"k8s.io/component-base/version/verflag"
	"k8s.io/utils/ptr"
	controllerruntime "sigs.k8s.io/controller-runtime"
	controllerconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/gardener/cert-management/pkg/certman2/apis/config"
	configv1alpha1 "github.com/gardener/cert-management/pkg/certman2/apis/config/v1alpha1"
	certmanclient "github.com/gardener/cert-management/pkg/certman2/client"
	"github.com/gardener/cert-management/pkg/certman2/controller/issuer"
)

// Name is the name of the Cert Controller-Manager.
const Name = "Gardener Cert Controller-Manager"

var configDecoder runtime.Decoder

func init() {
	configScheme := runtime.NewScheme()
	schemeBuilder := runtime.NewSchemeBuilder(
		configv1alpha1.AddToScheme,
	)
	utilruntime.Must(schemeBuilder.AddToScheme(configScheme))
	configDecoder = serializer.NewCodecFactory(configScheme).UniversalDecoder()
}

// NewCommand returns a new controller-manager command.
func NewCommand() *cobra.Command {
	o := newOptions()
	cmd := &cobra.Command{
		Use:     "controller-manager",
		Aliases: []string{"cm"},
		Short:   "Runs cert controller manager",
		Long:    "Runs cert controller manager. This command runs typically in a pod in the cluster.",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			log, err := cmdutils.InitRun(cmd, o, Name)
			if err != nil {
				return err
			}

			if err := o.run(cmd.Context(), log); err != nil {
				log.Error(err, "controller-manager run failed")
			}
			return nil
		},
	}

	flags := cmd.Flags()
	o.addFlags(flags)
	verflag.AddFlags(flags)

	return cmd
}

// options is a struct to support packages command.
type options struct {
	configFile string
	config     *config.CertManagerConfiguration
}

// newOptions returns initialized options.
func newOptions() *options {
	return &options{}
}

// addFlags binds the command options to a given flagset.
func (o *options) addFlags(flags *pflag.FlagSet) {
	flags.StringVar(&o.configFile, "config", o.configFile, "Path to configuration file.")
}

// Complete adapts from the command line args to the data required.
func (o *options) Complete() error {
	if len(o.configFile) == 0 {
		return fmt.Errorf("missing config file")
	}

	data, err := os.ReadFile(o.configFile)
	if err != nil {
		return fmt.Errorf("error reading config file: %w", err)
	}

	o.config = &config.CertManagerConfiguration{}
	if err = runtime.DecodeInto(configDecoder, data, o.config); err != nil {
		return fmt.Errorf("error decoding config: %w", err)
	}

	return nil
}

// Validate validates the provided command options.
func (o *options) Validate() error {
	return nil
}

// LogConfig returns the logging config.
func (o *options) LogConfig() (logLevel, logFormat string) {
	return o.config.LogLevel, o.config.LogFormat
}

// run does the actual work of the command.
func (o *options) run(ctx context.Context, log logr.Logger) error {
	cfg := o.config

	log.Info("Getting rest config")
	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		cfg.CertManagerClientConnection.Kubeconfig = kubeconfig
	}

	restConfig, err := kubernetes.RESTConfigFromClientConnectionConfiguration(&cfg.CertManagerClientConnection.ClientConnectionConfiguration, nil, kubernetes.AuthTokenFile)
	if err != nil {
		return err
	}

	var extraHandlers map[string]http.Handler
	if cfg.Debugging != nil && cfg.Debugging.EnableProfiling {
		extraHandlers = routes.ProfilingHandlers
		if cfg.Debugging.EnableContentionProfiling {
			goruntime.SetBlockProfileRate(1)
		}
	}

	log.Info("Setting up manager")
	mgr, err := manager.New(restConfig, manager.Options{
		Logger:                  log,
		Scheme:                  certmanclient.ClusterScheme,
		GracefulShutdownTimeout: ptr.To(5 * time.Second),

		HealthProbeBindAddress: net.JoinHostPort(cfg.Server.HealthProbes.BindAddress, strconv.Itoa(cfg.Server.HealthProbes.Port)),
		Metrics: metricsserver.Options{
			BindAddress:   net.JoinHostPort(cfg.Server.Metrics.BindAddress, strconv.Itoa(cfg.Server.Metrics.Port)),
			ExtraHandlers: extraHandlers,
		},

		LeaderElection:                cfg.LeaderElection.LeaderElect,
		LeaderElectionResourceLock:    cfg.LeaderElection.ResourceLock,
		LeaderElectionID:              cfg.LeaderElection.ResourceName,
		LeaderElectionNamespace:       cfg.LeaderElection.ResourceNamespace,
		LeaderElectionReleaseOnCancel: true,
		LeaseDuration:                 &cfg.LeaderElection.LeaseDuration.Duration,
		RenewDeadline:                 &cfg.LeaderElection.RenewDeadline.Duration,
		RetryPeriod:                   &cfg.LeaderElection.RetryPeriod.Duration,
		Controller: controllerconfig.Controller{
			RecoverPanic: ptr.To(true),
		},
	})
	if err != nil {
		return err
	}

	log.Info("Setting up health check endpoints")
	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return err
	}
	if err := mgr.AddReadyzCheck("informer-sync", gardenerhealthz.NewCacheSyncHealthz(mgr.GetCache())); err != nil {
		return err
	}

	scheme := mgr.GetScheme()
	if err := vpaautoscalingv1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("could not update manager scheme: %w", err)
	}

	if err := mgr.Add(&runner{
		mgr: mgr,
		cfg: cfg,
	}); err != nil {
		return err
	}

	log.Info("Starting manager")
	return mgr.Start(ctx)
}

// runner implements the Controller-Runtime's Runnable interface and is used to add further controllers
// while the manager already has been started.
type runner struct {
	mgr manager.Manager
	cfg *config.CertManagerConfiguration
}

func (r *runner) Start(ctx context.Context) error {
	log := r.mgr.GetLogger()

	waitForSyncCtx, waitForSyncCancel := context.WithTimeout(ctx, 5*time.Second)
	defer waitForSyncCancel()

	log.Info("Waiting for cache to be synced")
	if !r.mgr.GetCache().WaitForCacheSync(waitForSyncCtx) {
		return fmt.Errorf("failed waiting for cache to be synced")
	}

	clusterAccess, err := r.createClusterAccess()
	if err != nil {
		return fmt.Errorf("failed creating cluster access: %w", err)
	}

	log.Info("Adding controllers to manager")
	return addControllers(r.mgr, clusterAccess, r.cfg)
}

// TODO handle multi-cluster support
func (r *runner) createClusterAccess() (*certmanclient.ClusterAccess, error) {
	mainClientSet, err := kubernetes.NewWithConfig(
		kubernetes.WithRESTConfig(r.mgr.GetConfig()),
		kubernetes.WithRuntimeAPIReader(r.mgr.GetAPIReader()),
		kubernetes.WithRuntimeClient(r.mgr.GetClient()),
		kubernetes.WithClientConnectionOptions(r.cfg.CertManagerClientConnection.ClientConnectionConfiguration),
		kubernetes.WithRuntimeCache(r.mgr.GetCache()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed creating main clientset: %w", err)
	}

	return certmanclient.NewClusterAccess(r.mgr.GetLogger(), mainClientSet, nil, nil), nil
}

// addControllers adds the Controller-Manager controllers to the given manager.
func addControllers(
	mgr controllerruntime.Manager,
	clusterAccess *certmanclient.ClusterAccess,
	cfg *config.CertManagerConfiguration,
) error {
	if err := (&issuer.Reconciler{
		Config: *cfg,
	}).AddToManager(mgr, clusterAccess); err != nil {
		return fmt.Errorf("failed adding Issuer controller: %w", err)
	}

	return nil
}

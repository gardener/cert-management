package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	goruntime "runtime"
	"strconv"
	"syscall"
	"time"

	cmdutils "github.com/gardener/gardener/cmd/utils"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/controllerutils/routes"
	gardenerhealthz "github.com/gardener/gardener/pkg/healthz"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/component-base/version/verflag"
	"k8s.io/utils/ptr"
	controllerconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/gardener/cert-management/pkg/certman2/apis/config"
	configv1alpha1 "github.com/gardener/cert-management/pkg/certman2/apis/config/v1alpha1"
	certmanclient "github.com/gardener/cert-management/pkg/certman2/client"
)

// Name is the name of the Cert Controller-Manager.
const Name = "Gardener Cert Controller-Manager"

var configDecoder runtime.Decoder

func init() {
	configScheme := runtime.NewScheme()
	schemeBuilder := runtime.NewSchemeBuilder(
		config.AddToScheme,
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
		cfg.PrimaryClientConnection.Kubeconfig = kubeconfig
	}

	primaryRestConfig, err := kubernetes.RESTConfigFromClientConnectionConfiguration(&cfg.PrimaryClientConnection.ClientConnectionConfiguration, nil, kubernetes.AuthTokenFile)
	if err != nil {
		return err
	}
	secondaryRestConfig := primaryRestConfig
	if cfg.SecondaryClientConnection.Kubeconfig != "" {
		secondaryRestConfig, err = kubernetes.RESTConfigFromClientConnectionConfiguration(&cfg.SecondaryClientConnection.ClientConnectionConfiguration, nil, kubernetes.AuthTokenFile)
		if err != nil {
			return err
		}
	}

	var extraHandlers map[string]http.Handler
	if cfg.Debugging != nil && cfg.Debugging.EnableProfiling {
		extraHandlers = routes.ProfilingHandlers
		if cfg.Debugging.EnableContentionProfiling {
			goruntime.SetBlockProfileRate(1)
		}
	}

	log.Info("Setting up primary manager")
	primaryManager, err := manager.New(primaryRestConfig, manager.Options{
		Logger:                  log.WithName("primary"),
		Scheme:                  certmanclient.ClusterScheme,
		GracefulShutdownTimeout: ptr.To(5 * time.Second),

		HealthProbeBindAddress: net.JoinHostPort(cfg.Server.HealthProbes.BindAddress, strconv.Itoa(cfg.Server.HealthProbes.Port)),
		Metrics: metricsserver.Options{
			BindAddress: "0", // disable default metrics server
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
	log.Info("Setting up secondary manager")
	secondaryManager, err := manager.New(secondaryRestConfig, manager.Options{
		Logger:                  log.WithName("secondary"),
		Scheme:                  certmanclient.ClusterScheme,
		GracefulShutdownTimeout: ptr.To(5 * time.Second),

		HealthProbeBindAddress: net.JoinHostPort(cfg.Server.HealthProbes.BindAddress, strconv.Itoa(cfg.Server.HealthProbes.Port+1)),
		Metrics: metricsserver.Options{
			BindAddress: "0", // disable default metrics server
		},
		LeaderElection: false,
		Controller: controllerconfig.Controller{
			RecoverPanic: ptr.To(true),
		},
	})
	if err != nil {
		return err
	}

	if err := primaryManager.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return err
	}
	if err := primaryManager.AddReadyzCheck("informer-sync", gardenerhealthz.NewCacheSyncHealthz(primaryManager.GetCache())); err != nil {
		return err
	}
	if err := secondaryManager.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return err
	}
	if err := secondaryManager.AddReadyzCheck("informer-sync", gardenerhealthz.NewCacheSyncHealthz(primaryManager.GetCache())); err != nil {
		return err
	}

	if err := primaryManager.Add(&primaryRunner{
		mgr: primaryManager,
		cfg: cfg,
	}); err != nil {
		return err
	}
	if err := secondaryManager.Add(&secondaryRunner{
		mgr: secondaryManager,
		cfg: cfg,
	}); err != nil {
		return err
	}

	metricsAddr := net.JoinHostPort(cfg.Server.Metrics.BindAddress, strconv.Itoa(cfg.Server.Metrics.Port))
	managers := map[string]manager.Manager{"primary": primaryManager, "secondary": secondaryManager}
	return o.startManagers(ctx, log, metricsAddr, extraHandlers, managers)
}

func (o *options) startManagers(
	cmdCtx context.Context,
	log logr.Logger,
	metricsAddr string,
	extraHandlers map[string]http.Handler,
	managers map[string]manager.Manager,
) error {
	log.Info("Starting primary and issuer manager")

	// Create a context that is cancelled on SIGINT or SIGTERM
	ctx, cancel := context.WithCancel(cmdCtx)
	defer cancel()

	// Set up signal handling for graceful shutdown
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	results := make(chan error, len(managers)+1)
	mux := http.NewServeMux()
	handler := promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{
		ErrorHandling: promhttp.HTTPErrorOnError,
	})
	mux.Handle("/metrics", handler)
	for path, extraHandler := range extraHandlers {
		mux.Handle(path, extraHandler)
	}

	log.Info("starting metrics server")
	srv := newServer(mux)
	idleConnsClosed := make(chan struct{})
	go func() {
		<-ctx.Done()
		log.Info("Shutting down metrics server with timeout of 10 seconds")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			// Error from closing listeners, or context timeout
			log.Error(err, "error shutting down the HTTP server")
		}
		close(idleConnsClosed)
	}()

	log.Info("Serving metrics server", "bindAddress", metricsAddr)
	go func() {
		var err error
		if ln, err2 := net.Listen("tcp", metricsAddr); err2 != nil {
			err = fmt.Errorf("unable to listen at %s: %w", metricsAddr, err2)
			cancel()
		} else if err2 = srv.Serve(ln); err2 != nil && err2 != http.ErrServerClosed {
			err = fmt.Errorf("unable to start metrics server: %w", err)
			cancel()
		}
		results <- err
	}()

	// Start each manager in its own goroutine
	for name, mgr := range managers {
		go func(mgr manager.Manager) {
			var err error
			if err2 := mgr.Start(ctx); err2 != nil {
				err = fmt.Errorf("manager %s failed: %w", name, err2)
				cancel() // cancel all other managers on error
			}
			results <- err
		}(mgr)
	}

	// Wait for a signal
	<-signals
	log.Info("Received shutdown signal")
	cancel() // signal all managers to shut down

	var errs []error
	for err := range results {
		errs = append(errs, err)
	}
	log.Info("All managers stopped")
	return errors.Join(errs...)
}

func newServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		MaxHeaderBytes:    1 << 20,
		IdleTimeout:       90 * time.Second, // matches http.DefaultTransport keep-alive timeout
		ReadHeaderTimeout: 32 * time.Second,
	}
}

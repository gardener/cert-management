// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

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

	cmdutils "github.com/gardener/gardener/cmd/utils/initrun"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/controllerutils/routes"
	gardenerhealthz "github.com/gardener/gardener/pkg/healthz"
	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/component-base/version/verflag"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	controllerconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/gardener/cert-management/pkg/certman2/apis/config"
	configv1alpha1 "github.com/gardener/cert-management/pkg/certman2/apis/config/v1alpha1"
	certmanclient "github.com/gardener/cert-management/pkg/certman2/client"
	"github.com/gardener/cert-management/pkg/certman2/controller/certificate"
	issuercontrolplane "github.com/gardener/cert-management/pkg/certman2/controller/issuer/controlplane"
	"github.com/gardener/cert-management/pkg/certman2/controller/source"
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
		log.Info("Using kubeconfig from environment variable KUBECONFIG", "KUBECONFIG", kubeconfig)
		cfg.ClientConnection.Kubeconfig = kubeconfig
	}

	restConfig, err := kubernetes.RESTConfigFromClientConnectionConfiguration(&cfg.ClientConnection.ClientConnectionConfiguration, nil, kubernetes.AuthTokenFile)
	if err != nil {
		return err
	}
	controlPlaneRestConfig := restConfig
	if cfg.ControlPlaneClientConnection.Kubeconfig != "" {
		log.Info("Using control plane kubeconfig", "kubeconfig", cfg.ControlPlaneClientConnection.Kubeconfig)
		controlPlaneRestConfig, err = kubernetes.RESTConfigFromClientConnectionConfiguration(&cfg.ControlPlaneClientConnection.ClientConnectionConfiguration, nil, kubernetes.AuthTokenFile)
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

	log.Info("Setting up manager")
	mgr, err := manager.New(restConfig, manager.Options{
		Logger:                  log,
		Scheme:                  certmanclient.ClusterScheme,
		GracefulShutdownTimeout: ptr.To(5 * time.Second),
		Cache: cache.Options{
			SyncPeriod: &cfg.ClientConnection.CacheResyncPeriod.Duration,
		},

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
	var controlPlaneCluster cluster.Cluster = mgr
	if controlPlaneRestConfig != restConfig {
		log.Info("Setting up cluster object for target")
		controlPlaneCluster, err = cluster.New(controlPlaneRestConfig, func(opts *cluster.Options) {
			opts.Scheme = certmanclient.ClusterScheme
			opts.Logger = log

			// use dynamic rest mapper for secondary cluster, which will automatically rediscover resources on NoMatchErrors
			// but is rate-limited to not issue to many discovery calls (rate-limit shared across all reconciliations)
			opts.MapperProvider = apiutil.NewDynamicRESTMapper

			opts.Cache.DefaultNamespaces = map[string]cache.Config{cfg.Controllers.Issuer.Namespace: {}}
			opts.Cache.SyncPeriod = &cfg.ControlPlaneClientConnection.CacheResyncPeriod.Duration

			opts.Client.Cache = &client.CacheOptions{
				DisableFor: []client.Object{
					&corev1.Event{},
				},
			}
		})
		if err != nil {
			return fmt.Errorf("could not instantiate control plane cluster: %w", err)
		}

		log.Info("Setting up ready check for control plane informer sync")
		if err := mgr.AddReadyzCheck("control-plane-informer-sync", gardenerhealthz.NewCacheSyncHealthz(controlPlaneCluster.GetCache())); err != nil {
			return err
		}

		log.Info("Adding control plane cluster to manager")
		if err := mgr.Add(controlPlaneCluster); err != nil {
			return fmt.Errorf("failed adding control plane cluster to manager: %w", err)
		}
	}

	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return err
	}
	if err := mgr.AddReadyzCheck("informer-sync", gardenerhealthz.NewCacheSyncHealthz(mgr.GetCache())); err != nil {
		return err
	}

	log.Info("Adding source controllers to manager")
	tmpClient, err := client.New(restConfig, client.Options{
		Scheme: certmanclient.ClusterScheme,
	})
	if err != nil {
		return fmt.Errorf("creating prestart client failed: %w", err)
	}
	if err := source.AddToManager(mgr, cfg, tmpClient); err != nil {
		return fmt.Errorf("could not add source controllers to manager: %w", err)
	}

	log.Info("Adding controllers to manager")
	if err := (&certificate.Reconciler{
		Config: *cfg,
	}).AddToManager(mgr); err != nil {
		return fmt.Errorf("failed adding Certificate controller: %w", err)
	}
	if err := (&issuercontrolplane.Reconciler{
		Config: *cfg,
	}).AddToManager(mgr, controlPlaneCluster); err != nil {
		return fmt.Errorf("failed adding control plane Issuer controller: %w", err)
	}

	log.Info("Starting manager")
	return mgr.Start(ctx)
}

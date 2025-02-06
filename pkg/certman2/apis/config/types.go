package config

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	componentbaseconfig "k8s.io/component-base/config"
	componentbaseconfigv1alpha1 "k8s.io/component-base/config/v1alpha1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CertManagerConfiguration defines the configuration for the Gardener cert-manager.
type CertManagerConfiguration struct {
	metav1.TypeMeta
	// ClientConnection specifies the kubeconfig file and the client connection settings for primary
	// cluster containing the certificate and source resources the cert-manager should work on.
	ClientConnection *ClientConnection
	// ControlPlaneClientConnection contains client connection configurations
	// for the cluster containing the provided issuers.
	// If not set, the primary cluster is used.
	ControlPlaneClientConnection *ControlPlaneClientConnection
	// DNSClientConnection contains client connection configurations
	// for the cluster used to manage DNS resources for DNS challenges.
	// If not set, the secondary cluster is used.
	DNSClientConnection *DNSClientConnection
	LeaderElection      componentbaseconfig.LeaderElectionConfiguration
	// LogLevel is the level/severity for the logs. Must be one of [info,debug,error].
	LogLevel string
	// LogFormat is the output format for the logs. Must be one of [text,json].
	LogFormat string
	// Server defines the configuration of the HTTP server.
	Server ServerConfiguration
	// Debugging holds configuration for Debugging related features.
	Debugging *componentbaseconfig.DebuggingConfiguration
	// Controllers defines the configuration of the controllers.
	Controllers ControllerConfiguration
	// Class is the "cert.gardener.cloud/class" the cert-controller-manager is responsible for.
	// If not set, the default class "gardencert" is used.
	Class string
}

// ClientConnection contains client connection configurations
// for the primary cluster (certificates and source resources).
type ClientConnection struct {
	componentbaseconfigv1alpha1.ClientConnectionConfiguration
	// CacheResyncPeriod specifies the duration how often the cache for the cluster is resynced.
	CacheResyncPeriod *metav1.Duration
}

// ControlPlaneClientConnection contains client connection configurations
// for the cluster containing the provided issuers.
type ControlPlaneClientConnection struct {
	componentbaseconfigv1alpha1.ClientConnectionConfiguration
	// CacheResyncPeriod specifies the duration how often the cache for the cluster is resynced.
	CacheResyncPeriod *metav1.Duration
}

// DNSClientConnection contains client connection configurations
// for the cluster used to manage DNS resources for DNS challenges.
type DNSClientConnection struct {
	componentbaseconfigv1alpha1.ClientConnectionConfiguration
}

// ServerConfiguration contains details for the HTTP(S) servers.
type ServerConfiguration struct {
	// Webhooks is the configuration for the HTTPS webhook server.
	Webhooks Server
	// HealthProbes is the configuration for serving the healthz and readyz endpoints.
	HealthProbes *Server
	// Metrics is the configuration for serving the metrics endpoint.
	Metrics *Server
}

// Server contains information for HTTP(S) server configuration.
type Server struct {
	// BindAddress is the IP address on which to listen for the specified port.
	BindAddress string
	// Port is the port on which to serve requests.
	Port int
}

// ControllerConfiguration defines the configuration of the controllers.
type ControllerConfiguration struct {
	// Issuer is the configuration for the issuer controller.
	Issuer IssuerControllerConfig
}

// IssuerControllerConfig is the configuration for the issuer controller.
type IssuerControllerConfig struct {
	// ConcurrentSyncs is the number of concurrent worker routines for this controller.
	ConcurrentSyncs *int
	// SyncPeriod is the duration how often the controller performs its reconciliation.
	SyncPeriod *metav1.Duration
	// Namespace is the namespace on the secondary cluster containing the provided issuers.
	Namespace string
	// DefaultIssuerName is the name of the provided default issuer
	DefaultIssuerName string
	// DefaultRequestsPerDayQuota defines the maximum requests per day for ACME issuers
	DefaultRequestsPerDayQuota int
}

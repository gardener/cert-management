package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	componentbaseconfigv1alpha1 "k8s.io/component-base/config/v1alpha1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CertManagerConfiguration defines the configuration for the Gardener cert-manager.
type CertManagerConfiguration struct {
	metav1.TypeMeta `json:",inline"`
	// PrimaryClientConnection specifies the kubeconfig file and the client connection settings for primary
	// cluster containing the certificate and source resources the cert-manager should work on.
	PrimaryClientConnection *PrimaryClientConnection `json:"primaryClientConnection,omitempty"`
	// SecondaryClientConnection contains client connection configurations
	// for the cluster containing the provided issuers.
	// If not set, the primary cluster is used.
	// +optional
	SecondaryClientConnection *SecondaryClientConnection `json:"secondaryClientConnection,omitempty"`
	// DNSClientConnection contains client connection configurations
	// for the cluster used to manage DNS resources for DNS challenges.
	// If not set, the secondary cluster is used.
	// +optional
	DNSClientConnection *DNSClientConnection `json:"dnsClientConnection,omitempty"`
	// LeaderElection defines the configuration of leader election client.
	LeaderElection componentbaseconfigv1alpha1.LeaderElectionConfiguration `json:"leaderElection"`
	// LogLevel is the level/severity for the logs. Must be one of [info,debug,error].
	LogLevel string `json:"logLevel"`
	// LogFormat is the output format for the logs. Must be one of [text,json].
	LogFormat string `json:"logFormat"`
	// Server defines the configuration of the HTTP server.
	Server ServerConfiguration `json:"server"`
	// Debugging holds configuration for Debugging related features.
	// +optional
	Debugging *componentbaseconfigv1alpha1.DebuggingConfiguration `json:"debugging,omitempty"`
	// Controllers defines the configuration of the controllers.
	Controllers ControllerConfiguration `json:"controllers"`
}

// PrimaryClientConnection contains client connection configurations
// for the primary cluster (certificates and source resources).
type PrimaryClientConnection struct {
	componentbaseconfigv1alpha1.ClientConnectionConfiguration
}

// SecondaryClientConnection contains client connection configurations
// for the cluster containing the provided issuers.
type SecondaryClientConnection struct {
	componentbaseconfigv1alpha1.ClientConnectionConfiguration
}

// DNSClientConnection contains client connection configurations
// for the cluster used to manage DNS resources for DNS challenges.
type DNSClientConnection struct {
	componentbaseconfigv1alpha1.ClientConnectionConfiguration
}

// ServerConfiguration contains details for the HTTP(S) servers.
type ServerConfiguration struct {
	// Webhooks is the configuration for the HTTPS webhook server.
	Webhooks Server `json:"webhooks"`
	// HealthProbes is the configuration for serving the healthz and readyz endpoints.
	// +optional
	HealthProbes *Server `json:"healthProbes,omitempty"`
	// Metrics is the configuration for serving the metrics endpoint.
	// +optional
	Metrics *Server `json:"metrics,omitempty"`
}

// Server contains information for HTTP(S) server configuration.
type Server struct {
	// BindAddress is the IP address on which to listen for the specified port.
	BindAddress string `json:"bindAddress"`
	// Port is the port on which to serve requests.
	Port int `json:"port"`
}

// ControllerConfiguration defines the configuration of the controllers.
type ControllerConfiguration struct {
	// Issuer is the configuration for the issuer controller.
	Issuer IssuerControllerConfig `json:"issuer"`
}

// IssuerControllerConfig is the configuration for the issuer controller.
type IssuerControllerConfig struct {
	// ConcurrentSyncs is the number of concurrent worker routines for this controller.
	// +optional
	ConcurrentSyncs *int `json:"concurrentSyncs,omitempty"`
	// SyncPeriod is the duration how often the controller performs its reconciliation.
	// +optional
	SyncPeriod *metav1.Duration `json:"syncPeriod,omitempty"`
	// Namespace is the namespace on the secondary cluster containing the provided issuers.
	Namespace string `json:"namespace"`
}

const (
	// DefaultLockObjectNamespace is the default lock namespace for leader election.
	DefaultLockObjectNamespace = "kube-system"
	// DefaultLockObjectName is the default lock name for leader election.
	DefaultLockObjectName = "gardener-cert-manager-leader-election"
)

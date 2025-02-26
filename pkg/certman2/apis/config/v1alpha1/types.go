// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	componentbaseconfigv1alpha1 "k8s.io/component-base/config/v1alpha1"
)

// DefaultClass is the default cert-class
const DefaultClass = "gardencert"

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CertManagerConfiguration defines the configuration for the Gardener cert-manager.
type CertManagerConfiguration struct {
	metav1.TypeMeta `json:",inline"`
	// ClientConnection specifies the kubeconfig file and the client connection settings for primary
	// cluster containing the certificate and source resources the cert-manager should work on.
	ClientConnection *ClientConnection `json:"clientConnection,omitempty"`
	// ControlPlaneClientConnection contains client connection configurations
	// for the cluster containing the provided issuers.
	// If not set, the primary cluster is used.
	// +optional
	ControlPlaneClientConnection *ControlPlaneClientConnection `json:"controlPlaneClientConnection,omitempty"`
	// DNSClientConnection contains client connection configurations
	// for the cluster used to manage DNS resources for DNS challenges.
	// If not set, the control plane cluster is used.
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
	// Class is the "cert.gardener.cloud/class" the cert-controller-manager is responsible for.
	// If not set, the default class "gardencert" is used.
	Class string `json:"class"`
}

// ClientConnection contains client connection configurations
// for the primary cluster (certificates and source resources).
type ClientConnection struct {
	componentbaseconfigv1alpha1.ClientConnectionConfiguration
	// CacheResyncPeriod specifies the duration how often the cache for the cluster is resynced.
	CacheResyncPeriod *metav1.Duration `json:"cacheResyncPeriod"`
}

// ControlPlaneClientConnection contains client connection configurations
// for the cluster containing the provided issuers.
type ControlPlaneClientConnection struct {
	componentbaseconfigv1alpha1.ClientConnectionConfiguration
	// CacheResyncPeriod specifies the duration how often the cache for the cluster is resynced.
	CacheResyncPeriod *metav1.Duration `json:"cacheResyncPeriod"`
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
	// DefaultIssuerName is the name of the provided default issuer
	DefaultIssuerName string `json:"defaultIssuerName"`
	// DefaultRequestsPerDayQuota defines the maximum requests per day for ACME issuers
	DefaultRequestsPerDayQuota int `json:"defaultRequestsPerDayQuota"`
}

const (
	// DefaultLockObjectNamespace is the default lock namespace for leader election.
	DefaultLockObjectNamespace = "kube-system"
	// DefaultLockObjectName is the default lock name for leader election.
	DefaultLockObjectName = "gardener-cert-controller-manager-leader-election"
)

package v1alpha1

import (
	"time"

	"github.com/gardener/gardener/pkg/logger"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	componentbaseconfigv1alpha1 "k8s.io/component-base/config/v1alpha1"
	"k8s.io/utils/ptr"
)

func addDefaultingFuncs(scheme *runtime.Scheme) error {
	return RegisterDefaults(scheme)
}

// SetDefaults_CertManagerConfiguration sets defaults for the configuration of the Gardener cert-manager.
func SetDefaults_CertManagerConfiguration(obj *CertManagerConfiguration) {
	if obj.LogLevel == "" {
		obj.LogLevel = logger.InfoLevel
	}
	if obj.LogFormat == "" {
		obj.LogFormat = logger.FormatJSON
	}
	if obj.PrimaryClientConnection == nil {
		obj.PrimaryClientConnection = &PrimaryClientConnection{}
	}
	if obj.SecondaryClientConnection == nil {
		obj.SecondaryClientConnection = &SecondaryClientConnection{}
	}
	if obj.DNSClientConnection == nil {
		obj.DNSClientConnection = &DNSClientConnection{}
	}
}

// SetDefaults_PrimaryClientConnection sets defaults for the primary client connection.
func SetDefaults_PrimaryClientConnection(obj *PrimaryClientConnection) {
	if obj.QPS == 0.0 {
		obj.QPS = 100.0
	}
	if obj.Burst == 0 {
		obj.Burst = 130
	}
}

// SetDefaults_SecondaryClientConnection sets defaults for the secondary client connection.
func SetDefaults_SecondaryClientConnection(obj *SecondaryClientConnection) {
	if obj.QPS == 0.0 {
		obj.QPS = 100.0
	}
	if obj.Burst == 0 {
		obj.Burst = 130
	}
}

// SetDefaults_DNSClientConnection sets defaults for the primary client connection.
func SetDefaults_DNSClientConnection(obj *DNSClientConnection) {
	if obj.QPS == 0.0 {
		obj.QPS = 100.0
	}
	if obj.Burst == 0 {
		obj.Burst = 130
	}
}

// SetDefaults_LeaderElectionConfiguration sets defaults for the leader election of the Gardener operator.
func SetDefaults_LeaderElectionConfiguration(obj *componentbaseconfigv1alpha1.LeaderElectionConfiguration) {
	if obj.ResourceLock == "" {
		// Don't use a constant from the client-go resourcelock package here (resourcelock is not an API package, pulls
		// in some other dependencies and is thereby not suitable to be used in this API package).
		obj.ResourceLock = "leases"
	}

	componentbaseconfigv1alpha1.RecommendedDefaultLeaderElectionConfiguration(obj)

	if obj.ResourceNamespace == "" {
		obj.ResourceNamespace = DefaultLockObjectNamespace
	}
	if obj.ResourceName == "" {
		obj.ResourceName = DefaultLockObjectName
	}
}

// SetDefaults_ServerConfiguration sets defaults for the server configuration.
func SetDefaults_ServerConfiguration(obj *ServerConfiguration) {
	if obj.HealthProbes == nil {
		obj.HealthProbes = &Server{}
	}
	if obj.HealthProbes.Port == 0 {
		obj.HealthProbes.Port = 2751
	}

	if obj.Metrics == nil {
		obj.Metrics = &Server{}
	}
	if obj.Metrics.Port == 0 {
		obj.Metrics.Port = 2753
	}
}

// SetDefaults_IssuerControllerConfig sets defaults for the IssuerControllerConfig object.
func SetDefaults_IssuerControllerConfig(obj *IssuerControllerConfig) {
	if obj.ConcurrentSyncs == nil {
		obj.ConcurrentSyncs = ptr.To(1)
	}
	if obj.SyncPeriod == nil {
		obj.SyncPeriod = &metav1.Duration{Duration: time.Hour}
	}
	if obj.Namespace == "" {
		obj.Namespace = "default"
	}
	if obj.DefaultIssuerName == "" {
		obj.DefaultIssuerName = "default-issuer"
	}
	if obj.DefaultRequestsPerDayQuota == 0 {
		obj.DefaultRequestsPerDayQuota = 10000
	}
}

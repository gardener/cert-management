package v1alpha1_test

import (
	"time"

	"github.com/gardener/gardener/pkg/logger"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	componentbaseconfigv1alpha1 "k8s.io/component-base/config/v1alpha1"
	"k8s.io/utils/ptr"

	. "github.com/gardener/cert-management/pkg/certman2/apis/config/v1alpha1"
)

var _ = Describe("Defaults", func() {
	Describe("CertManagerConfiguration", func() {
		var obj *CertManagerConfiguration

		BeforeEach(func() {
			obj = &CertManagerConfiguration{}
		})

		It("should correctly default the configuration", func() {
			SetObjectDefaults_CertManagerConfiguration(obj)

			Expect(obj.LogLevel).To(Equal(logger.InfoLevel))
			Expect(obj.LogFormat).To(Equal(logger.FormatJSON))

			Expect(obj.Server.HealthProbes.BindAddress).To(BeEmpty())
			Expect(obj.Server.HealthProbes.Port).To(Equal(2751))
			Expect(obj.Server.Metrics.BindAddress).To(BeEmpty())
			Expect(obj.Server.Metrics.Port).To(Equal(2753))
		})

		It("should not overwrite custom settings", func() {
			var (
				expectedLogLevel  = "foo"
				expectedLogFormat = "bar"
				expectedServer    = ServerConfiguration{
					HealthProbes: &Server{
						BindAddress: "baz",
						Port:        1,
					},
					Metrics: &Server{
						BindAddress: "bax",
						Port:        2,
					},
				}
			)

			obj.LogLevel = expectedLogLevel
			obj.LogFormat = expectedLogFormat
			obj.Server = expectedServer

			SetObjectDefaults_CertManagerConfiguration(obj)

			Expect(obj.LogLevel).To(Equal(expectedLogLevel))
			Expect(obj.LogFormat).To(Equal(expectedLogFormat))
			Expect(obj.Server).To(Equal(expectedServer))
		})

		Describe("RuntimeClientConnection", func() {
			It("should not default ContentType and AcceptContentTypes", func() {
				SetObjectDefaults_CertManagerConfiguration(obj)

				// ContentType fields will be defaulted by client constructors / controller-runtime based on whether a
				// given APIGroup supports protobuf or not. defaults must not touch these, otherwise the integelligent
				// logic will be overwritten
				Expect(obj.PrimaryClientConnection.ContentType).To(BeEmpty())
				Expect(obj.PrimaryClientConnection.AcceptContentTypes).To(BeEmpty())
			})

			It("should correctly default PrimaryClientConnection", func() {
				SetObjectDefaults_CertManagerConfiguration(obj)

				Expect(obj.PrimaryClientConnection).NotTo(BeNil())
				Expect(obj.PrimaryClientConnection.ClientConnectionConfiguration).To(Equal(componentbaseconfigv1alpha1.ClientConnectionConfiguration{
					QPS:   100.0,
					Burst: 130,
				}))
			})

			It("should correctly default SecondaryClientConnection", func() {
				SetObjectDefaults_CertManagerConfiguration(obj)

				Expect(obj.SecondaryClientConnection).NotTo(BeNil())
				Expect(obj.SecondaryClientConnection.ClientConnectionConfiguration).To(Equal(componentbaseconfigv1alpha1.ClientConnectionConfiguration{
					QPS:   100.0,
					Burst: 130,
				}))
			})

			It("should correctly default DNSClientConnection", func() {
				SetObjectDefaults_CertManagerConfiguration(obj)

				Expect(obj.DNSClientConnection).NotTo(BeNil())
				Expect(obj.DNSClientConnection.ClientConnectionConfiguration).To(Equal(componentbaseconfigv1alpha1.ClientConnectionConfiguration{
					QPS:   100.0,
					Burst: 130,
				}))
			})
		})

		Describe("leader election settings", func() {
			It("should correctly default leader election settings", func() {
				SetObjectDefaults_CertManagerConfiguration(obj)

				Expect(obj.LeaderElection).NotTo(BeNil())
				Expect(obj.LeaderElection.LeaderElect).To(PointTo(BeTrue()))
				Expect(obj.LeaderElection.LeaseDuration).To(Equal(metav1.Duration{Duration: 15 * time.Second}))
				Expect(obj.LeaderElection.RenewDeadline).To(Equal(metav1.Duration{Duration: 10 * time.Second}))
				Expect(obj.LeaderElection.RetryPeriod).To(Equal(metav1.Duration{Duration: 2 * time.Second}))
				Expect(obj.LeaderElection.ResourceLock).To(Equal("leases"))
				Expect(obj.LeaderElection.ResourceNamespace).To(Equal("kube-system"))
				Expect(obj.LeaderElection.ResourceName).To(Equal("gardener-cert-manager-leader-election"))
			})

			It("should not overwrite custom settings", func() {
				expectedLeaderElection := componentbaseconfigv1alpha1.LeaderElectionConfiguration{
					LeaderElect:       ptr.To(true),
					ResourceLock:      "foo",
					RetryPeriod:       metav1.Duration{Duration: 40 * time.Second},
					RenewDeadline:     metav1.Duration{Duration: 41 * time.Second},
					LeaseDuration:     metav1.Duration{Duration: 42 * time.Second},
					ResourceNamespace: "other-garden-ns",
					ResourceName:      "lock-object",
				}
				obj.LeaderElection = expectedLeaderElection
				SetObjectDefaults_CertManagerConfiguration(obj)

				Expect(obj.LeaderElection).To(Equal(expectedLeaderElection))
			})
		})

		Describe("Controller configuration", func() {
			Describe("Issuer controller", func() {
				It("should default the object", func() {
					obj := &IssuerControllerConfig{}

					SetDefaults_IssuerControllerConfig(obj)

					Expect(obj.ConcurrentSyncs).To(PointTo(Equal(1)))
					Expect(obj.SyncPeriod).To(PointTo(Equal(metav1.Duration{Duration: time.Hour})))
					Expect(obj.Namespace).To(Equal("default"))
					Expect(obj.DefaultRequestsPerDayQuota).To(Equal(10000))
					Expect(obj.DefaultIssuerName).To(Equal("default-issuer"))
				})

				It("should not overwrite existing values", func() {
					obj := &IssuerControllerConfig{
						ConcurrentSyncs:            ptr.To(5),
						SyncPeriod:                 &metav1.Duration{Duration: time.Second},
						Namespace:                  "foo",
						DefaultIssuerName:          "foo-issuer",
						DefaultRequestsPerDayQuota: 10,
					}

					SetDefaults_IssuerControllerConfig(obj)

					Expect(obj.ConcurrentSyncs).To(PointTo(Equal(5)))
					Expect(obj.SyncPeriod).To(PointTo(Equal(metav1.Duration{Duration: time.Second})))
					Expect(obj.Namespace).To(Equal("foo"))
					Expect(obj.DefaultRequestsPerDayQuota).To(Equal(10))
					Expect(obj.DefaultIssuerName).To(Equal("foo-issuer"))
				})
			})
		})
	})
})

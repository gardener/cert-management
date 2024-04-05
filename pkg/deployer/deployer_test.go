package deployer_test

import (
	"context"
	"fmt"

	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	"github.com/gardener/gardener/pkg/component"
	componenttest "github.com/gardener/gardener/pkg/component/test"
	"github.com/gardener/gardener/pkg/resourcemanager/controller/garbagecollector/references"
	. "github.com/gardener/gardener/pkg/utils/test/matchers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	. "github.com/gardener/cert-management/pkg/deployer"
)

var _ = Describe("Deployer", func() {
	var (
		ctx = context.Background()

		namespace = "some-namespace"
		image     = "some-image:some-tag"

		c      client.Client
		values Values

		managedResource       *resourcesv1alpha1.ManagedResource
		managedResourceSecret *corev1.Secret
		serviceAccount        *corev1.ServiceAccount
		clusterRole           *rbacv1.ClusterRole
		clusterRoleBinding    *rbacv1.ClusterRoleBinding
		deployment            *appsv1.Deployment
		role                  *rbacv1.Role
		roleBinding           *rbacv1.RoleBinding

		newComponent = func(values Values) component.DeployWaiter {
			return New(c, values)
		}

		checkDeployment func(deploy *appsv1.Deployment, expectedLen int)

		expectedCRDs = []string{
			"certificaterevocations.cert.gardener.cloud",
			"certificates.cert.gardener.cloud",
			"issuers.cert.gardener.cloud",
		}
	)

	BeforeEach(func() {
		c = fakeclient.NewClientBuilder().WithScheme(Scheme).Build()

		values = Values{
			Image:     image,
			Name:      "cert-controller-manager",
			Namespace: namespace,
			PodLabels: map[string]string{
				"networking.gardener.cloud/to-dns":               "allowed",
				"networking.gardener.cloud/to-runtime-apiserver": "allowed",
				"networking.gardener.cloud/to-public-networks":   "allowed",
				"networking.gardener.cloud/to-private-networks":  "allowed",
			},
			Config: Configuration{
				HttpServerPort: 8080,
			},
			ManagedResourceConfig: ManagedResourceConfig{
				Namespace:      "mr-test",
				Labels:         map[string]string{"test/component": "cert-management"},
				InjectedLabels: map[string]string{"test/component": "cert-management"},
				Class:          "myclass",
			},
		}
		serviceAccount = &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cert-controller-manager",
				Namespace: namespace,
			},
		}
		clusterRole = &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: "cert-controller-manager",
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"services"},
					Verbs:     []string{"get", "list", "update", "watch"},
				},
				{
					APIGroups: []string{"networking.k8s.io"},
					Resources: []string{"ingresses"},
					Verbs:     []string{"get", "list", "update", "watch"},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"secrets"},
					Verbs:     []string{"get", "list", "update", "watch", "create", "delete"},
				},
				{
					APIGroups: []string{"cert.gardener.cloud"},
					Resources: []string{
						"issuers", "issuers/status",
						"certificates", "certificates/status",
						"certificaterevocations", "certificaterevocations/status",
					},
					Verbs: []string{"get", "list", "update", "watch", "create", "delete"},
				},
				{
					APIGroups: []string{""},
					Resources: []string{"events"},
					Verbs:     []string{"create", "patch"},
				},
				{
					APIGroups: []string{"apiextensions.k8s.io"},
					Resources: []string{"customresourcedefinitions"},
					Verbs:     []string{"get", "list", "update", "create"},
				},
			},
		}
		clusterRoleBinding = &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "cert-controller-manager",
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     "cert-controller-manager",
			},
			Subjects: []rbacv1.Subject{{
				Kind:      "ServiceAccount",
				Name:      "cert-controller-manager",
				Namespace: namespace,
			}},
		}
		role = &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cert-controller-manager",
				Namespace: namespace,
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"coordination.k8s.io"},
					Resources: []string{"leases"},
					Verbs:     []string{"create"},
				},
				{
					APIGroups:     []string{"coordination.k8s.io"},
					Resources:     []string{"leases"},
					ResourceNames: []string{"cert-controller-manager-controllers"},
					Verbs:         []string{"get", "watch", "update", "patch"},
				},
				{
					APIGroups: []string{"dns.gardener.cloud"},
					Resources: []string{"dnsentries"},
					Verbs:     []string{"get", "list", "update", "watch", "create", "delete"},
				},
			},
		}
		roleBinding = &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      role.Name,
				Namespace: namespace,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      rbacv1.ServiceAccountKind,
					Name:      serviceAccount.Name,
					Namespace: serviceAccount.Namespace,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "Role",
				Name:     role.Name,
			},
		}
		deployment = &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cert-controller-manager",
				Namespace: namespace,
				Labels: map[string]string{
					resourcesv1alpha1.HighAvailabilityConfigType: resourcesv1alpha1.HighAvailabilityConfigTypeController,
					"app.kubernetes.io/instance":                 "cert-management",
					"app.kubernetes.io/name":                     "cert-management",
				},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas:             ptr.To[int32](1),
				RevisionHistoryLimit: ptr.To[int32](5),
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app.kubernetes.io/instance": "cert-management",
						"app.kubernetes.io/name":     "cert-management",
					},
				},
				Strategy: appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"app.kubernetes.io/instance":                     "cert-management",
							"app.kubernetes.io/name":                         "cert-management",
							"networking.gardener.cloud/to-dns":               "allowed",
							"networking.gardener.cloud/to-runtime-apiserver": "allowed",
							"networking.gardener.cloud/to-public-networks":   "allowed",
							"networking.gardener.cloud/to-private-networks":  "allowed",
						},
					},
					Spec: corev1.PodSpec{
						ServiceAccountName: serviceAccount.Name,
						Containers: []corev1.Container{{
							Name:            "cert-management",
							Image:           image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Args: []string{
								"--name=cert-controller-manager",
								"--dns-namespace=some-namespace",
								"--issuer.issuer-namespace=some-namespace",
								"--server-port-http=8080",
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path:   "/healthz",
										Port:   intstr.FromInt32(8080),
										Scheme: "HTTP",
									},
								},
								InitialDelaySeconds: 30,
								TimeoutSeconds:      5,
								PeriodSeconds:       10,
								SuccessThreshold:    1,
								FailureThreshold:    3,
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("64Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("200m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
							},
							Ports: []corev1.ContainerPort{{
								ContainerPort: 8080,
								Protocol:      corev1.ProtocolTCP,
							}},
						}},
					},
				},
			},
		}
	})

	checkDeployment = func(deploy *appsv1.Deployment, expectedLen int) {
		Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResource), managedResource)).To(Succeed())
		expectedMrDeployment := &resourcesv1alpha1.ManagedResource{
			ObjectMeta: metav1.ObjectMeta{
				Name:            ManagedResourceName,
				Namespace:       "mr-test",
				ResourceVersion: "1",
				Labels:          map[string]string{"test/component": "cert-management"},
			},
			Spec: resourcesv1alpha1.ManagedResourceSpec{
				Class:        ptr.To("myclass"),
				InjectLabels: map[string]string{"test/component": "cert-management"},
				SecretRefs: []corev1.LocalObjectReference{{
					Name: managedResource.Spec.SecretRefs[0].Name,
				}},
				KeepObjects: ptr.To(false),
			},
		}
		utilruntime.Must(references.InjectAnnotations(expectedMrDeployment))
		Expect(managedResource).To(DeepEqual(expectedMrDeployment))

		managedResourceSecret.Name = managedResource.Spec.SecretRefs[0].Name
		Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResourceSecret), managedResourceSecret)).To(Succeed())
		Expect(managedResourceSecret.Type).To(Equal(corev1.SecretTypeOpaque))
		Expect(managedResourceSecret.Immutable).To(Equal(ptr.To(true)))
		Expect(managedResourceSecret.Labels["resources.gardener.cloud/garbage-collectable-reference"]).To(Equal("true"))
		Expect(managedResourceSecret.Data).To(HaveLen(expectedLen))

		for _, name := range expectedCRDs {
			Expect(managedResourceSecret.Data[fmt.Sprintf("customresourcedefinition____%s.yaml", name)]).NotTo(BeNil(), name)
		}

		Expect(string(managedResourceSecret.Data["serviceaccount__"+namespace+"__cert-controller-manager.yaml"])).To(Equal(componenttest.Serialize(serviceAccount)))
		Expect(string(managedResourceSecret.Data["clusterrole____cert-controller-manager.yaml"])).To(Equal(componenttest.Serialize(clusterRole)))
		Expect(string(managedResourceSecret.Data["clusterrolebinding____cert-controller-manager.yaml"])).To(Equal(componenttest.Serialize(clusterRoleBinding)))
		Expect(string(managedResourceSecret.Data["role__"+namespace+"__cert-controller-manager.yaml"])).To(Equal(componenttest.Serialize(role)))
		Expect(string(managedResourceSecret.Data["rolebinding__"+namespace+"__cert-controller-manager.yaml"])).To(Equal(componenttest.Serialize(roleBinding)))
		Expect(string(managedResourceSecret.Data["deployment__"+namespace+"__cert-controller-manager.yaml"])).To(Equal(componenttest.Serialize(deploy)))
	}

	JustBeforeEach(func() {

		managedResource = &resourcesv1alpha1.ManagedResource{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ManagedResourceName,
				Namespace: "mr-test",
				Labels: map[string]string{
					"test/component": "cert-management",
				},
			},
		}
		managedResourceSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "managedresource-" + managedResource.Name,
				Namespace: "mr-test",
				Labels: map[string]string{
					"test/component": "cert-management",
				},
			},
		}
	})

	Describe("#Deploy", func() {
		It("should successfully deploy", func() {
			comp := newComponent(values)

			Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResource), managedResource)).To(MatchError(apierrors.NewNotFound(schema.GroupResource{Group: resourcesv1alpha1.SchemeGroupVersion.Group, Resource: "managedresources"}, managedResource.Name)))

			Expect(comp.Deploy(ctx)).To(Succeed())

			checkDeployment(deployment, 9)
		})

		It("should successfully deploy with caCertificates", func() {
			bundleData := "-----BEGIN CERTIFICATE-----\nXXX\n-----END CERTIFICATE-----"
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cert-controller-manager",
					Namespace: "deploytest",
				},
				Data: map[string][]byte{
					"bundle.crt": []byte(bundleData),
				},
			}
			Expect(c.Create(ctx, secret)).To(Succeed())
			values.Config.CACertificateBundle = ptr.To(bundleData)
			comp := newComponent(values)

			Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResource), managedResource)).To(MatchError(apierrors.NewNotFound(schema.GroupResource{Group: resourcesv1alpha1.SchemeGroupVersion.Group, Resource: "managedresources"}, managedResource.Name)))

			Expect(comp.Deploy(ctx)).To(Succeed())

			deploy := *deployment
			container := &deploy.Spec.Template.Spec.Containers[0]
			container.Env = []corev1.EnvVar{
				{
					Name:  "LEGO_CA_SYSTEM_CERT_POOL",
					Value: "true",
				},
				{
					Name:  "LEGO_CA_CERTIFICATES",
					Value: "/var/run/cert-manager/certs/bundle.crt",
				},
			}
			container.VolumeMounts = []corev1.VolumeMount{
				{
					Name:      "ca-certificates",
					MountPath: "/var/run/cert-manager/certs",
					ReadOnly:  true,
				},
			}
			expectedSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secret.Name + "-79db81ac",
					Namespace: namespace,
					Labels: map[string]string{
						"resources.gardener.cloud/garbage-collectable-reference": "true",
					},
				},
				Immutable: ptr.To(true),
				Data:      secret.Data,
				Type:      secret.Type,
			}
			deploy.Spec.Template.Spec.Volumes = []corev1.Volume{
				{
					Name: "ca-certificates",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: expectedSecret.Name,
						},
					},
				},
			}
			utilruntime.Must(references.InjectAnnotations(&deploy))

			checkDeployment(&deploy, 10)

			Expect(string(managedResourceSecret.Data["secret__"+namespace+"__cert-controller-manager-79db81ac.yaml"])).To(Equal(componenttest.Serialize(expectedSecret)))
		})
	})

	Describe("#Destroy", func() {
		It("should successfully destroy all resources", func() {
			comp := newComponent(values)

			Expect(c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: managedResource.Namespace}})).To(Succeed())
			Expect(c.Create(ctx, managedResource)).To(Succeed())
			Expect(c.Create(ctx, managedResourceSecret)).To(Succeed())

			Expect(comp.Destroy(ctx)).To(Succeed())

			Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResource), managedResource)).To(MatchError(apierrors.NewNotFound(schema.GroupResource{Group: resourcesv1alpha1.SchemeGroupVersion.Group, Resource: "managedresources"}, managedResource.Name)))
			Expect(c.Get(ctx, client.ObjectKeyFromObject(managedResourceSecret), managedResourceSecret)).To(MatchError(apierrors.NewNotFound(schema.GroupResource{Group: corev1.SchemeGroupVersion.Group, Resource: "secrets"}, managedResourceSecret.Name)))
		})
	})
})

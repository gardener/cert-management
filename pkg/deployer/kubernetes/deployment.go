/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package kubernetes

import (
	"fmt"

	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	"github.com/gardener/gardener/pkg/resourcemanager/controller/garbagecollector/references"
	gardenerutils "github.com/gardener/gardener/pkg/utils"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/utils/ptr"
)

// EmptyDeployment returns an apps/v1 Deployment with basic metadata filled only.
func EmptyDeployment(name string, namespace string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
}

// MutateDeployment adjusts the given 'deployment' for 'cert-management' to the desired spec.
func MutateDeployment(
	deployment *appsv1.Deployment,
	podLabels map[string]string,
	serviceAccountName string,
	image string,
	serverPort int32,
	caBundleSecret *corev1.Secret,
) {
	deployment.Labels = getDeploymentLabels()
	metav1.SetMetaDataLabel(&deployment.ObjectMeta, resourcesv1alpha1.HighAvailabilityConfigType, resourcesv1alpha1.HighAvailabilityConfigTypeController)

	deployment.Spec = appsv1.DeploymentSpec{
		Replicas:             ptr.To(int32(1)),
		RevisionHistoryLimit: ptr.To(int32(5)),
		Selector:             &metav1.LabelSelector{MatchLabels: getDeploymentLabels()},
		Strategy:             appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType},
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Labels: gardenerutils.MergeStringMaps(getDeploymentLabels(), podLabels),
			},
			Spec: corev1.PodSpec{
				ServiceAccountName: serviceAccountName,
				Containers: []corev1.Container{{
					Name:            "cert-management",
					Image:           image,
					ImagePullPolicy: corev1.PullIfNotPresent,
					Args: []string{
						"--name=cert-controller-manager",
						fmt.Sprintf("--dns-namespace=%s", deployment.Namespace),
						fmt.Sprintf("--issuer.issuer-namespace=%s", deployment.Namespace),
						fmt.Sprintf("--server-port-http=%d", serverPort),
					},
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Path:   "/healthz",
								Port:   intstr.FromInt32(serverPort),
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
						ContainerPort: serverPort,
						Protocol:      corev1.ProtocolTCP,
					}},
				}},
			},
		},
	}

	if caBundleSecret != nil {
		container := &deployment.Spec.Template.Spec.Containers[0]
		container.Env = append(container.Env,
			corev1.EnvVar{
				Name:  "LEGO_CA_SYSTEM_CERT_POOL",
				Value: "true",
			},
			corev1.EnvVar{
				Name:  "LEGO_CA_CERTIFICATES",
				Value: "/var/run/cert-manager/certs/bundle.crt",
			},
		)
		container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
			Name:      "ca-certificates",
			ReadOnly:  true,
			MountPath: "/var/run/cert-manager/certs",
		})
		deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: "ca-certificates",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: caBundleSecret.Name,
				},
			},
		})
	}
	utilruntime.Must(references.InjectAnnotations(deployment))
}

func getDeploymentLabels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":     "cert-management",
		"app.kubernetes.io/instance": "cert-management",
	}
}

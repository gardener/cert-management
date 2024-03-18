/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package kubernetes

import (
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterRole return a new rbac/v1 ClusterRole object for 'cert-management'.
func ClusterRole(name string) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
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
}

// ClusterRoleBinding return a new rbac/v1 ClusterRoleBinding object for 'cert-management'.
func ClusterRoleBinding(name, clusterRoleName, serviceAccountName, serviceAccountNamespace string) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     clusterRoleName,
		},
		Subjects: []rbacv1.Subject{{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      serviceAccountName,
			Namespace: serviceAccountNamespace,
		}},
	}
}

// Role return a new rbac/v1 Role object for 'cert-management'.
func Role(name, namespace string) *rbacv1.Role {
	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
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
				Verbs:         []string{"get", "watch", "update"},
			},
			{
				APIGroups: []string{"dns.gardener.cloud"},
				Resources: []string{"dnsentries"},
				Verbs:     []string{"get", "list", "update", "watch", "create", "delete"},
			},
		},
	}
}

// RoleBinding return a new rbac/v1 RoleBinding object for 'cert-management'.
func RoleBinding(name, namespace, serviceAccountName, roleName string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      serviceAccountName,
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     roleName,
		},
	}
}

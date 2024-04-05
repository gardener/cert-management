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

// EmptyClusterRole returns a rbac/v1 ClusterRole with basic metadata filled only.
func EmptyClusterRole(name string) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
}

// ReconcileClusterRole adjusts the given 'clusterRole' for 'cert-management' to the desired spec.
func ReconcileClusterRole(clusterRole *rbacv1.ClusterRole) {
	clusterRole.Rules = []rbacv1.PolicyRule{
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
	}
}

// EmptyClusterRoleBinding returns a rbac/v1 ClusterRoleBinding with basic metadata filled only.
func EmptyClusterRoleBinding(name string) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
}

// ReconcileClusterRoleBinding adjusts the given 'clusterRoleBinding' for 'cert-management' to the desired spec.
func ReconcileClusterRoleBinding(clusterRoleBinding *rbacv1.ClusterRoleBinding, clusterRoleName, serviceAccountName, serviceAccountNamespace string) {
	clusterRoleBinding.RoleRef = rbacv1.RoleRef{
		APIGroup: rbacv1.GroupName,
		Kind:     "ClusterRole",
		Name:     clusterRoleName,
	}
	clusterRoleBinding.Subjects = []rbacv1.Subject{{
		Kind:      rbacv1.ServiceAccountKind,
		Name:      serviceAccountName,
		Namespace: serviceAccountNamespace,
	}}
}

// EmptyRole returns a rbac/v1 Role with basic metadata filled only.
func EmptyRole(name, namespace string) *rbacv1.Role {
	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
}

// ReconcileRole adjusts the given 'role' for 'cert-management' to the desired spec.
func ReconcileRole(role *rbacv1.Role) {
	role.Rules = []rbacv1.PolicyRule{
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
	}
}

// EmptyRoleBinding returns a rbac/v1 RoleBinding with basic metadata filled only.
func EmptyRoleBinding(name, namespace string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
}

// ReconcileRoleBinding adjusts the given 'roleBinding' for 'cert-management' to the desired spec.
func ReconcileRoleBinding(roleBinding *rbacv1.RoleBinding, serviceAccountName, roleName string) {
	roleBinding.Subjects = []rbacv1.Subject{{
		Kind:      rbacv1.ServiceAccountKind,
		Name:      serviceAccountName,
		Namespace: roleBinding.Namespace,
	}}

	roleBinding.RoleRef = rbacv1.RoleRef{
		APIGroup: rbacv1.GroupName,
		Kind:     "Role",
		Name:     roleName,
	}
}

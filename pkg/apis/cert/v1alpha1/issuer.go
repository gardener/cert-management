/*
 * Copyright 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 *
 */

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// IssuerList is the list of Issuers
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type IssuerList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata
	// More info: http://releases.k8s.io/HEAD/docs/devel/api-conventions.md#metadata
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Issuer `json:"items"`
}

// Issuer is the issuer CR.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type Issuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              IssuerSpec   `json:"spec"`
	Status            IssuerStatus `json:"status"`
}

// IssuerSpec is the spec of the issuer.
type IssuerSpec struct {
	// ACME is the ACME protocol specific spec.
	// +optional
	ACME *ACMESpec `json:"acme,omitempty"`
	// RequestsPerDayQuota is the maximum number of certificate requests per days allowed for this issuer
	// +optional
	RequestsPerDayQuota *int `json:"requestsPerDayQuota,omitempty"`
}

// ACMESpec is the ACME specific part of the spec.
type ACMESpec struct {
	// Server is the URL of the ACME server.
	Server string `json:"server"`
	// Email is the email address to use for user registration.
	Email string `json:"email"`

	// AutoRegistration is the flag if automatic registration should be applied if needed.
	// +optional
	AutoRegistration bool `json:"autoRegistration,omitempty"`

	// PrivateKeySecretRef is the secret ref to the ACME private key.
	// +optional
	PrivateKeySecretRef *corev1.SecretReference `json:"privateKeySecretRef,omitempty"`
}

// IssuerStatus is the status of the issuer.
type IssuerStatus struct {
	// ObservedGeneration is the observed generation of the spec.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// State is either empty, 'Pending', 'Error', or 'Ready'.
	State string `json:"state"`
	// Message is the status or error message.
	Message *string `json:"message,omitempty"`
	// Type is the issuer type. Currently only 'acme' is supported.
	Type *string `json:"type"`
	// ACME is the ACME specific status.
	ACME *runtime.RawExtension `json:"acme,omitempty"`
	// RequestsPerDayQuota is the actual maximum number of certificate requests per days allowed for this issuer
	RequestsPerDayQuota int `json:"requestsPerDayQuota,omitempty"`
}

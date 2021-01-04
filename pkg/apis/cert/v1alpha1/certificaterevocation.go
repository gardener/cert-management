/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CertificateRevocationList is the list of Certificate revocation items.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type CertificateRevocationList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata
	// More info: http://releases.k8s.io/HEAD/docs/devel/api-conventions.md#metadata
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CertificateRevocation `json:"items"`
}

// CertificateRevocation is the certificate revocation custom resource.
// +kubebuilder:storageversion
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,path=certificaterevocations,shortName=certrevoke,singular=certificaterevocation
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name=CERTIFICATE,description="Certificate to be revoked",JSONPath=".spec.certificateRef.name",type=string
// +kubebuilder:printcolumn:name=STATUS,JSONPath=".status.state",type=string,description="status of revocation"
// +kubebuilder:printcolumn:name=REVOKED_AT,JSONPath=".status.revocationApplied",priority=500,type=date,description="timestamp of complete revocation"
// +kubebuilder:printcolumn:name=RENEW,JSONPath=".spec.renew",type=boolean,description="if true certificate objects should be renewed before revoking old certificates certificate(s)"
// +kubebuilder:printcolumn:name=QUALIFIED_AT,JSONPath=".spec.qualifyingDate",type=date,description="qualifying all certificates valid before this timestamp"
// +kubebuilder:printcolumn:name=AGE,JSONPath=".metadata.creationTimestamp",type=date,description="object creation timestamp"
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type CertificateRevocation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              CertificateRevocationSpec `json:"spec"`
	// +optional
	Status CertificateRevocationStatus `json:"status,omitempty"`
}

// CertificateRevocationSpec is the spec of the certificate revocation.
type CertificateRevocationSpec struct {
	// CertificateRef is the references to the certificate to be revoked
	CertificateRef CertificateRef `json:"certificateRef,omitempty"`
	// Renew specifies if certificate objects should be renewed before revoking old certificates
	// +optional
	Renew *bool `json:"renew,omitempty"`
	// QualifyingDate specifies that any certificate with the same DNS names like the given 'certificateRef' should be revoked
	// if it is valid before this date. If not specified, it will be filled with the current time.
	// +optional
	QualifyingDate *metav1.Time `json:"qualifyingDate,omitempty"`
}

// CertificateRef is the reference of the issuer by name.
type CertificateRef struct {
	// Name is the name of the certificate in the same namespace.
	Name string `json:"name"`
	// Namespace is the namespace of the certificate CR.
	Namespace string `json:"namespace"`
}

// CertificateSecretRef is a reference to a secret together with the serial number
type CertificateSecretRef struct {
	corev1.SecretReference `json:",inline"`
	// SerialNumber is the serial number of the certificate
	SerialNumber string `json:"serialNumber"`
}

// CertificateRevocationStatus is the status of the certificate request.
type CertificateRevocationStatus struct {
	// ObservedGeneration is the observed generation of the spec.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// State is the certificate state.
	State string `json:"state"`
	// Message is the status or error message.
	Message *string `json:"message,omitempty"`
	// ObjectStatuses contains the statuses of the involved certificate objects
	// +optional
	Objects *ObjectStatuses `json:"objects,omitempty"`
	// SecretStatuses contains the statuses of the involved certificate secrets
	// +optional
	Secrets *SecretStatuses `json:"secrets,omitempty"`
	// RevocationApplied is the timestamp when the revocation was completed
	// +optional
	RevocationApplied *metav1.Time `json:"revocationApplied,omitempty"`
}

// ObjectStatuses contains the statuses of the involved certificate objects
type ObjectStatuses struct {
	// Processing is the list of certificate objects to be processed
	// +optional
	Processing []CertificateRef `json:"processing,omitempty"`
	// Renewed is the list of certificate objects successfully renewed
	// +optional
	Renewed []CertificateRef `json:"renewed,omitempty"`
	// Revoked is the list of certificate objects successfully revoked (without renewal)
	// +optional
	Revoked []CertificateRef `json:"revoked,omitempty"`
	// Failed is the list of certificate objects whose processing failed
	// +optional
	Failed []CertificateRef `json:"failed,omitempty"`
}

// SecretStatuses contains the statuses of the involved certificate secrets
type SecretStatuses struct {
	// Processing is the list of certificate secrets to be processed
	// +optional
	Processing []CertificateSecretRef `json:"processing,omitempty"`
	// Revoked is the list of certificate secrets successfully revoked
	// +optional
	Revoked []CertificateSecretRef `json:"revoked,omitempty"`
	// Failed is the list of certificate secrets whose revocation failed
	// +optional
	Failed []CertificateSecretRef `json:"failed,omitempty"`
}

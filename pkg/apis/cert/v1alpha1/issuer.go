/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
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
// +kubebuilder:storageversion
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,path=issuers,shortName=issuer,singular=issuer
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name=SERVER,description="ACME Server",JSONPath=".spec.acme.server",type=string
// +kubebuilder:printcolumn:name=EMAIL,description="ACME Registration email",JSONPath=".spec.acme.email",type=string
// +kubebuilder:printcolumn:name=STATUS,JSONPath=".status.state",type=string,description="Status of registration"
// +kubebuilder:printcolumn:name=TYPE,JSONPath=".status.type",type=string,description="Issuer type"
// +kubebuilder:printcolumn:name=AGE,JSONPath=".metadata.creationTimestamp",type=date,description="object creation timestamp"
// +kubebuilder:printcolumn:name=INCLUDED_DOMAINS,JSONPath=".spec.acme.domains.include",priority=2000,type=string,description="included domains"
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type Issuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              IssuerSpec `json:"spec"`
	// +optional
	Status IssuerStatus `json:"status"`
}

// IssuerSpec is the spec of the issuer.
type IssuerSpec struct {
	// ACME is the ACME protocol specific spec.
	// +optional
	ACME *ACMESpec `json:"acme,omitempty"`
	// CA is the CA specific spec.
	// +optional
	CA *CASpec `json:"ca,omitempty"`
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

	// ACMEExternalAccountBinding is a reference to a CA external account of the ACME server.
	// +optional
	ExternalAccountBinding *ACMEExternalAccountBinding `json:"externalAccountBinding,omitempty"`

	// SkipDNSChallengeValidation marks that this issuer does not validate DNS challenges.
	// In this case no DNS entries/records are created for a DNS Challenge and DNS propagation
	// is not checked.
	// +optional
	SkipDNSChallengeValidation *bool `json:"skipDNSChallengeValidation,omitempty"`

	// Domains optionally specifies domains allowed or forbidden for certificate requests
	// +optional
	Domains *DNSSelection `json:"domains,omitempty"`
}

// DNSSelection is a restriction on the domains to be allowed or forbidden for certificate requests
type DNSSelection struct {
	// Include are domain names for which certificate requests are allowed (including any subdomains)
	//+ optional
	Include []string `json:"include,omitempty"`
	// Exclude are domain names for which certificate requests are forbidden (including any subdomains)
	// + optional
	Exclude []string `json:"exclude,omitempty"`
}

// ACMEExternalAccountBinding is a reference to a CA external account of the ACME server.
type ACMEExternalAccountBinding struct {
	// keyID is the ID of the CA key that the External Account is bound to.
	KeyID string `json:"keyID"`

	// keySecretRef is the secret ref to the
	// Secret which holds the symmetric MAC key of the External Account Binding with data key 'hmacKey'.
	// The secret key stored in the Secret **must** be un-padded, base64 URL
	// encoded data.
	KeySecretRef *corev1.SecretReference `json:"keySecretRef"`
}

// CASpec is the CA specific part of the spec.
type CASpec struct {
	// PrivateKeySecretRef is the secret ref to the CA secret.
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
	// +optional
	Message *string `json:"message,omitempty"`
	// Type is the issuer type. Currently only 'acme' and 'ca' are supported.
	// +optional
	Type *string `json:"type"`
	// ACME is the ACME specific status.
	// +kubebuilder:validation:XPreserveUnknownFields
	// +kubebuilder:pruning:PreserveUnknownFields
	// +optional
	ACME *runtime.RawExtension `json:"acme,omitempty"`
	// CA is the CA specific status.
	// +kubebuilder:validation:XPreserveUnknownFields
	// +kubebuilder:pruning:PreserveUnknownFields
	// +optional
	CA *runtime.RawExtension `json:"ca,omitempty"`
	// RequestsPerDayQuota is the actual maximum number of certificate requests per days allowed for this issuer
	// +optional
	RequestsPerDayQuota int `json:"requestsPerDayQuota,omitempty"`
}

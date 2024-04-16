/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// CertificateList is the list of Certificate items.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type CertificateList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata
	// More info: http://releases.k8s.io/HEAD/docs/devel/api-conventions.md#metadata
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Certificate `json:"items"`
}

// Certificate is the certificate CR.
// +kubebuilder:storageversion
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,path=certificates,shortName=cert,singular=certificate
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name=COMMON NAME,description="Subject domain name of certificate",JSONPath=".status.commonName",type=string
// +kubebuilder:printcolumn:name=ISSUER,description="Issuer name",JSONPath=".status.issuerRef.name",type=string
// +kubebuilder:printcolumn:name=STATUS,JSONPath=".status.state",type=string,description="Status of registration"
// +kubebuilder:printcolumn:name=EXPIRATION_DATE,JSONPath=".status.expirationDate",priority=500,type=string,description="Expiration date (not valid anymore after this date)"
// +kubebuilder:printcolumn:name=DNS_NAMES,JSONPath=".status.dnsNames",priority=2000,type=string,description="Domains names in subject alternative names"
// +kubebuilder:printcolumn:name=AGE,JSONPath=".metadata.creationTimestamp",type=date,description="object creation timestamp"
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type Certificate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              CertificateSpec `json:"spec"`
	// +optional
	Status CertificateStatus `json:"status,omitempty"`
}

// CertificateSpec is the spec of the certificate to request.
type CertificateSpec struct {
	// CommonName is the CN for the certificate (max. 64 chars).
	// +optional
	// +kubebuilder:validation:MaxLength=64
	CommonName *string `json:"commonName,omitempty"`
	// DNSNames are the optional additional domain names of the certificate.
	// +optional
	DNSNames []string `json:"dnsNames,omitempty"`
	// CSR is the alternative way to provide CN,DNSNames and other information.
	// +optional
	CSR []byte `json:"csr,omitempty"`
	// IssuerRef is the reference of the issuer to use.
	// +optional
	IssuerRef *IssuerRef `json:"issuerRef,omitempty"`
	// SecretName is the name of the secret object to use for storing the certificate.
	// +optional
	SecretName *string `json:"secretName,omitempty"`
	// SecretRef is the reference of the secret object to use for storing the certificate.
	// +optional
	SecretRef *corev1.SecretReference `json:"secretRef,omitempty"`
	// SecretLabels are labels to add to the certificate secret.
	// +optional
	SecretLabels map[string]string `json:"secretLabels,omitempty"`
	// Renew triggers a renewal if set to true
	// +optional
	Renew *bool `json:"renew,omitempty"`
	// EnsureRenewedAfter specifies a time stamp in the past. Renewing is only triggered if certificate notBefore date is before this date.
	// +optional
	EnsureRenewedAfter *metav1.Time `json:"ensureRenewedAfter,omitempty"`
	// FollowCNAME if true delegated domain for DNS01 challenge is used if CNAME record for DNS01 challange domain `_acme-challenge.<domain>` is set.
	// +optional
	FollowCNAME *bool `json:"followCNAME,omitempty"`
	// Keystores configures additional keystore output formats stored in the `secretName`/`secretRef` Secret resource.
	// +optional
	Keystores *CertificateKeystores `json:"keystores,omitempty"`
	// PreferredChain allows to specify the preferred certificate chain: if the CA offers multiple certificate chains, prefer the chain with an issuer matching this Subject Common Name. If no match, the default offered chain will be used.
	// +optional
	PreferredChain *string `json:"preferredChain,omitempty"`
	// Private key options. These include the key algorithm and size.
	// +optional
	PrivateKey *CertificatePrivateKey `json:"privateKey,omitempty"`
}

// IssuerRef is the reference of the issuer by name.
type IssuerRef struct {
	// Name is the name of the issuer (in the configured issuer namespace on default cluster or namespace on target cluster as given).
	Name string `json:"name"`
	// Namespace is the namespace of the issuer, only needed if issuer is defined on target cluster
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// PrivateKeyAlgorithm is the type for the algorithm.
// +kubebuilder:validation:Enum=RSA;ECDSA
type PrivateKeyAlgorithm string

const (
	// RSAKeyAlgorithm is the value to use the RSA algorithm for the private key.
	RSAKeyAlgorithm PrivateKeyAlgorithm = "RSA"

	// ECDSAKeyAlgorithm is the value to use the ECDSA algorithm for the private key.
	ECDSAKeyAlgorithm PrivateKeyAlgorithm = "ECDSA"
)

// PrivateKeySize is the size for the algorithm.
// +kubebuilder:validation:Enum=256;384;2048;3072;4096
type PrivateKeySize int32

// CertificatePrivateKey contains configuration options for private keys
// used by the Certificate controller.
// These include the key algorithm and size.
type CertificatePrivateKey struct {
	// Algorithm is the private key algorithm of the corresponding private key
	// for this certificate.
	//
	// If provided, allowed values are either `RSA` or `ECDSA`.
	// If `algorithm` is specified and `size` is not provided,
	// deployment specific default values will be used.
	// +optional
	Algorithm *PrivateKeyAlgorithm `json:"algorithm,omitempty"`

	// Size is the key bit size of the corresponding private key for this certificate.
	//
	// If `algorithm` is set to `RSA`, valid values are `2048`, `3072` or `4096`,
	// and will default to a deployment specific value if not specified.
	// If `algorithm` is set to `ECDSA`, valid values are `256` or `384`,
	// and will default to a deployment specific value if not specified.
	// No other values are allowed.
	// +optional
	Size *PrivateKeySize `json:"size,omitempty"`
}

// BackOffState stores the status for exponential back off on repeated cert request failure
type BackOffState struct {
	// ObservedGeneration is the observed generation the BackOffState is assigned to
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// RetryAfter is the timestamp this cert request is not retried before.
	RetryAfter metav1.Time `json:"recheckAfter"`
	// RetryInterval is interval to wait for retrying.
	RetryInterval metav1.Duration `json:"recheckInterval"`
}

// CertificateStatus is the status of the certificate request.
type CertificateStatus struct {
	// ObservedGeneration is the observed generation of the spec.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// State is the certificate state.
	State string `json:"state"`
	// Message is the status or error message.
	// +optional
	Message *string `json:"message,omitempty"`
	// LastPendingTimestamp contains the start timestamp of the last pending status.
	// +optional
	LastPendingTimestamp *metav1.Time `json:"lastPendingTimestamp,omitempty"`
	// CommonName is the current CN.
	// +optional
	CommonName *string `json:"commonName,omitempty"`
	// DNSNames are the current domain names.
	// +optional
	DNSNames []string `json:"dnsNames,omitempty"`
	// IssuerRef is the used issuer.
	// +optional
	IssuerRef *QualifiedIssuerRef `json:"issuerRef,omitempty"`
	// ExpirationDate shows the notAfter validity date.
	// +optional
	ExpirationDate *string `json:"expirationDate,omitempty"`
	// BackOff contains the state to back off failed certificate requests
	// +optional
	BackOff *BackOffState `json:"backoff,omitempty"`
	// List of status conditions to indicate the status of certificates.
	// Known condition types are `Ready`.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

const (
	// CertificateConditionReady indicates that a certificate is ready for use.
	// This is defined as:
	// - The target secret exists
	// - The target secret contains a certificate that has not expired
	// - The target secret contains a private key valid for the certificate
	// - The commonName and dnsNames attributes match those specified on the Certificate
	CertificateConditionReady string = "Ready"
)

// QualifiedIssuerRef is the full qualified issuer reference.
type QualifiedIssuerRef struct {
	// Cluster is the cluster name of the issuer ('default' or 'target').
	// optional because of backwards compatibility
	// +optional
	Cluster string `json:"cluster,omitempty"`
	// Name is the name of the issuer.
	Name string `json:"name"`
	// Namespace is the namespace of the issuer.
	Namespace string `json:"namespace"`
}

// IsDefaultCluster returns true if the reference is on the default cluster.
func (r QualifiedIssuerRef) IsDefaultCluster() bool {
	return r.Cluster == "default"
}

// CertificateKeystores configures additional keystore output formats to be created in the Certificate's output Secret.
type CertificateKeystores struct {
	// JKS configures options for storing a JKS keystore in the `spec.secretName`/`spec.secretRef` Secret resource.
	// +optional
	JKS *JKSKeystore `json:"jks,omitempty"`

	// PKCS12 configures options for storing a PKCS12 keystore in the `spec.secretName`/`spec.secretRef` Secret resource.
	// +optional
	PKCS12 *PKCS12Keystore `json:"pkcs12,omitempty"`
}

// JKSKeystore configures options for storing a JKS keystore in the `spec.secretName`/`spec.secretRef` Secret resource.
type JKSKeystore struct {
	// Create enables JKS keystore creation for the Certificate.
	// If true, a file named `keystore.jks` will be created in the target
	// Secret resource, encrypted using the password stored in `passwordSecretRef`.
	// The keystore file will only be updated upon re-issuance.
	Create bool `json:"create"`

	// PasswordSecretRef is a reference to a key in a Secret resource
	// containing the password used to encrypt the JKS keystore.
	PasswordSecretRef SecretKeySelector `json:"passwordSecretRef"`
}

// PKCS12Keystore configures options for storing a PKCS12 keystore in the `spec.secretName`/`spec.secretRef` Secret resource.
type PKCS12Keystore struct {
	// Create enables PKCS12 keystore creation for the Certificate.
	// If true, a file named `keystore.p12` will be created in the target
	// Secret resource, encrypted using the password stored in `passwordSecretRef`.
	// The keystore file will only be updated upon re-issuance.
	Create bool `json:"create"`

	// PasswordSecretRef is a reference to a key in a Secret resource
	// containing the password used to encrypt the PKCS12 keystore.
	PasswordSecretRef SecretKeySelector `json:"passwordSecretRef"`
}

// SecretKeySelector is a reference to a key in a Secret resource in the same namespace.
type SecretKeySelector struct {
	// SecretName of the secret resource being referred to in the same namespace.
	SecretName string `json:"secretName"`

	// Key of the entry in the Secret resource's `data` field to be used.
	Key string `json:"key,omitempty"`
}

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
// +kubebuilder:resource:scope=Namespaced,path=issuers,singular=issuer
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

	// PrecheckNameservers overwrites the default precheck nameservers used for checking DNS propagation.
	// Format `host` or `host:port`, e.g. "8.8.8.8" same as "8.8.8.8:53" or "google-public-dns-a.google.com:53".
	// +optional
	PrecheckNameservers []string `json:"precheckNameservers,omitempty"`
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

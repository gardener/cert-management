/*
Copyright (c) YEAR SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file

SPDX-License-Identifier: Apache-2.0
*/

package crds

import (
	"github.com/gardener/controller-manager-library/pkg/resources/apiextensions"
	"github.com/gardener/controller-manager-library/pkg/utils"
)

var registry = apiextensions.NewRegistry()

func init() {
	var data string
	data = `
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    controller-gen.kubebuilder.io/version: v0.13.0
  name: certificaterevocations.cert.gardener.cloud
spec:
  group: cert.gardener.cloud
  names:
    kind: CertificateRevocation
    listKind: CertificateRevocationList
    plural: certificaterevocations
    shortNames:
    - certrevoke
    singular: certificaterevocation
  scope: Namespaced
  versions:
  - additionalPrinterColumns:
    - description: Certificate to be revoked
      jsonPath: .spec.certificateRef.name
      name: CERTIFICATE
      type: string
    - description: status of revocation
      jsonPath: .status.state
      name: STATUS
      type: string
    - description: timestamp of complete revocation
      jsonPath: .status.revocationApplied
      name: REVOKED_AT
      priority: 500
      type: date
    - description: if true certificate objects should be renewed before revoking old
        certificates certificate(s)
      jsonPath: .spec.renew
      name: RENEW
      type: boolean
    - description: qualifying all certificates valid before this timestamp
      jsonPath: .spec.qualifyingDate
      name: QUALIFIED_AT
      type: date
    - description: object creation timestamp
      jsonPath: .metadata.creationTimestamp
      name: AGE
      type: date
    name: v1alpha1
    schema:
      openAPIV3Schema:
        description: CertificateRevocation is the certificate revocation custom resource.
        properties:
          apiVersion:
            description: 'APIVersion defines the versioned schema of this representation
              of an object. Servers should convert recognized schemas to the latest
              internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources'
            type: string
          kind:
            description: 'Kind is a string value representing the REST resource this
              object represents. Servers may infer this from the endpoint the client
              submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds'
            type: string
          metadata:
            type: object
          spec:
            description: CertificateRevocationSpec is the spec of the certificate
              revocation.
            properties:
              certificateRef:
                description: CertificateRef is the references to the certificate to
                  be revoked
                properties:
                  name:
                    description: Name is the name of the certificate in the same namespace.
                    type: string
                  namespace:
                    description: Namespace is the namespace of the certificate CR.
                    type: string
                required:
                - name
                - namespace
                type: object
              qualifyingDate:
                description: QualifyingDate specifies that any certificate with the
                  same DNS names like the given 'certificateRef' should be revoked
                  if it is valid before this date. If not specified, it will be filled
                  with the current time.
                format: date-time
                type: string
              renew:
                description: Renew specifies if certificate objects should be renewed
                  before revoking old certificates
                type: boolean
            type: object
          status:
            description: CertificateRevocationStatus is the status of the certificate
              request.
            properties:
              message:
                description: Message is the status or error message.
                type: string
              objects:
                description: ObjectStatuses contains the statuses of the involved
                  certificate objects
                properties:
                  failed:
                    description: Failed is the list of certificate objects whose processing
                      failed
                    items:
                      description: CertificateRef is the reference of the issuer by
                        name.
                      properties:
                        name:
                          description: Name is the name of the certificate in the
                            same namespace.
                          type: string
                        namespace:
                          description: Namespace is the namespace of the certificate
                            CR.
                          type: string
                      required:
                      - name
                      - namespace
                      type: object
                    type: array
                  processing:
                    description: Processing is the list of certificate objects to
                      be processed
                    items:
                      description: CertificateRef is the reference of the issuer by
                        name.
                      properties:
                        name:
                          description: Name is the name of the certificate in the
                            same namespace.
                          type: string
                        namespace:
                          description: Namespace is the namespace of the certificate
                            CR.
                          type: string
                      required:
                      - name
                      - namespace
                      type: object
                    type: array
                  renewed:
                    description: Renewed is the list of certificate objects successfully
                      renewed
                    items:
                      description: CertificateRef is the reference of the issuer by
                        name.
                      properties:
                        name:
                          description: Name is the name of the certificate in the
                            same namespace.
                          type: string
                        namespace:
                          description: Namespace is the namespace of the certificate
                            CR.
                          type: string
                      required:
                      - name
                      - namespace
                      type: object
                    type: array
                  revoked:
                    description: Revoked is the list of certificate objects successfully
                      revoked (without renewal)
                    items:
                      description: CertificateRef is the reference of the issuer by
                        name.
                      properties:
                        name:
                          description: Name is the name of the certificate in the
                            same namespace.
                          type: string
                        namespace:
                          description: Namespace is the namespace of the certificate
                            CR.
                          type: string
                      required:
                      - name
                      - namespace
                      type: object
                    type: array
                type: object
              observedGeneration:
                description: ObservedGeneration is the observed generation of the
                  spec.
                format: int64
                type: integer
              revocationApplied:
                description: RevocationApplied is the timestamp when the revocation
                  was completed
                format: date-time
                type: string
              secrets:
                description: SecretStatuses contains the statuses of the involved
                  certificate secrets
                properties:
                  failed:
                    description: Failed is the list of certificate secrets whose revocation
                      failed
                    items:
                      description: CertificateSecretRef is a reference to a secret
                        together with the serial number
                      properties:
                        name:
                          description: name is unique within a namespace to reference
                            a secret resource.
                          type: string
                        namespace:
                          description: namespace defines the space within which the
                            secret name must be unique.
                          type: string
                        serialNumber:
                          description: SerialNumber is the serial number of the certificate
                          type: string
                      required:
                      - serialNumber
                      type: object
                      x-kubernetes-map-type: atomic
                    type: array
                  processing:
                    description: Processing is the list of certificate secrets to
                      be processed
                    items:
                      description: CertificateSecretRef is a reference to a secret
                        together with the serial number
                      properties:
                        name:
                          description: name is unique within a namespace to reference
                            a secret resource.
                          type: string
                        namespace:
                          description: namespace defines the space within which the
                            secret name must be unique.
                          type: string
                        serialNumber:
                          description: SerialNumber is the serial number of the certificate
                          type: string
                      required:
                      - serialNumber
                      type: object
                      x-kubernetes-map-type: atomic
                    type: array
                  revoked:
                    description: Revoked is the list of certificate secrets successfully
                      revoked
                    items:
                      description: CertificateSecretRef is a reference to a secret
                        together with the serial number
                      properties:
                        name:
                          description: name is unique within a namespace to reference
                            a secret resource.
                          type: string
                        namespace:
                          description: namespace defines the space within which the
                            secret name must be unique.
                          type: string
                        serialNumber:
                          description: SerialNumber is the serial number of the certificate
                          type: string
                      required:
                      - serialNumber
                      type: object
                      x-kubernetes-map-type: atomic
                    type: array
                type: object
              state:
                description: State is the certificate state.
                type: string
            required:
            - state
            type: object
        required:
        - spec
        type: object
    served: true
    storage: true
    subresources:
      status: {}
  `
	utils.Must(registry.RegisterCRD(data))
	data = `
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    controller-gen.kubebuilder.io/version: v0.13.0
  name: certificates.cert.gardener.cloud
spec:
  group: cert.gardener.cloud
  names:
    kind: Certificate
    listKind: CertificateList
    plural: certificates
    shortNames:
    - cert
    singular: certificate
  scope: Namespaced
  versions:
  - additionalPrinterColumns:
    - description: Subject domain name of certificate
      jsonPath: .status.commonName
      name: COMMON NAME
      type: string
    - description: Issuer name
      jsonPath: .status.issuerRef.name
      name: ISSUER
      type: string
    - description: Status of registration
      jsonPath: .status.state
      name: STATUS
      type: string
    - description: Expiration date (not valid anymore after this date)
      jsonPath: .status.expirationDate
      name: EXPIRATION_DATE
      priority: 500
      type: string
    - description: Domains names in subject alternative names
      jsonPath: .status.dnsNames
      name: DNS_NAMES
      priority: 2000
      type: string
    - description: object creation timestamp
      jsonPath: .metadata.creationTimestamp
      name: AGE
      type: date
    name: v1alpha1
    schema:
      openAPIV3Schema:
        description: Certificate is the certificate CR.
        properties:
          apiVersion:
            description: 'APIVersion defines the versioned schema of this representation
              of an object. Servers should convert recognized schemas to the latest
              internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources'
            type: string
          kind:
            description: 'Kind is a string value representing the REST resource this
              object represents. Servers may infer this from the endpoint the client
              submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds'
            type: string
          metadata:
            type: object
          spec:
            description: CertificateSpec is the spec of the certificate to request.
            properties:
              commonName:
                description: CommonName is the CN for the certificate (max. 64 chars).
                maxLength: 64
                type: string
              csr:
                description: CSR is the alternative way to provide CN,DNSNames and
                  other information.
                format: byte
                type: string
              dnsNames:
                description: DNSNames are the optional additional domain names of
                  the certificate.
                items:
                  type: string
                type: array
              ensureRenewedAfter:
                description: EnsureRenewedAfter specifies a time stamp in the past.
                  Renewing is only triggered if certificate notBefore date is before
                  this date.
                format: date-time
                type: string
              followCNAME:
                description: FollowCNAME if true delegated domain for DNS01 challenge
                  is used if CNAME record for DNS01 challange domain ` + "`" + `_acme-challenge.<domain>` + "`" + `
                  is set.
                type: boolean
              issuerRef:
                description: IssuerRef is the reference of the issuer to use.
                properties:
                  name:
                    description: Name is the name of the issuer (in the configured
                      issuer namespace on default cluster or namespace on target cluster
                      as given).
                    type: string
                  namespace:
                    description: Namespace is the namespace of the issuer, only needed
                      if issuer is defined on target cluster
                    type: string
                required:
                - name
                type: object
              keystores:
                description: Keystores configures additional keystore output formats
                  stored in the ` + "`" + `secretName` + "`" + `/` + "`" + `secretRef` + "`" + ` Secret resource.
                properties:
                  jks:
                    description: JKS configures options for storing a JKS keystore
                      in the ` + "`" + `spec.secretName` + "`" + `/` + "`" + `spec.secretRef` + "`" + ` Secret resource.
                    properties:
                      create:
                        description: Create enables JKS keystore creation for the
                          Certificate. If true, a file named ` + "`" + `keystore.jks` + "`" + ` will be
                          created in the target Secret resource, encrypted using the
                          password stored in ` + "`" + `passwordSecretRef` + "`" + `. The keystore file
                          will only be updated upon re-issuance.
                        type: boolean
                      passwordSecretRef:
                        description: PasswordSecretRef is a reference to a key in
                          a Secret resource containing the password used to encrypt
                          the JKS keystore.
                        properties:
                          key:
                            description: Key of the entry in the Secret resource's
                              ` + "`" + `data` + "`" + ` field to be used.
                            type: string
                          secretName:
                            description: SecretName of the secret resource being referred
                              to in the same namespace.
                            type: string
                        required:
                        - secretName
                        type: object
                    required:
                    - create
                    - passwordSecretRef
                    type: object
                  pkcs12:
                    description: PKCS12 configures options for storing a PKCS12 keystore
                      in the ` + "`" + `spec.secretName` + "`" + `/` + "`" + `spec.secretRef` + "`" + ` Secret resource.
                    properties:
                      create:
                        description: Create enables PKCS12 keystore creation for the
                          Certificate. If true, a file named ` + "`" + `keystore.p12` + "`" + ` will be
                          created in the target Secret resource, encrypted using the
                          password stored in ` + "`" + `passwordSecretRef` + "`" + `. The keystore file
                          will only be updated upon re-issuance.
                        type: boolean
                      passwordSecretRef:
                        description: PasswordSecretRef is a reference to a key in
                          a Secret resource containing the password used to encrypt
                          the PKCS12 keystore.
                        properties:
                          key:
                            description: Key of the entry in the Secret resource's
                              ` + "`" + `data` + "`" + ` field to be used.
                            type: string
                          secretName:
                            description: SecretName of the secret resource being referred
                              to in the same namespace.
                            type: string
                        required:
                        - secretName
                        type: object
                    required:
                    - create
                    - passwordSecretRef
                    type: object
                type: object
              preferredChain:
                description: 'PreferredChain allows to specify the preferred certificate
                  chain: if the CA offers multiple certificate chains, prefer the
                  chain with an issuer matching this Subject Common Name. If no match,
                  the default offered chain will be used.'
                type: string
              renew:
                description: Renew triggers a renewal if set to true
                type: boolean
              secretLabels:
                additionalProperties:
                  type: string
                description: SecretLabels are labels to add to the certificate secret.
                type: object
              secretName:
                description: SecretName is the name of the secret object to use for
                  storing the certificate.
                type: string
              secretRef:
                description: SecretRef is the reference of the secret object to use
                  for storing the certificate.
                properties:
                  name:
                    description: name is unique within a namespace to reference a
                      secret resource.
                    type: string
                  namespace:
                    description: namespace defines the space within which the secret
                      name must be unique.
                    type: string
                type: object
                x-kubernetes-map-type: atomic
            type: object
          status:
            description: CertificateStatus is the status of the certificate request.
            properties:
              backoff:
                description: BackOff contains the state to back off failed certificate
                  requests
                properties:
                  observedGeneration:
                    description: ObservedGeneration is the observed generation the
                      BackOffState is assigned to
                    format: int64
                    type: integer
                  recheckAfter:
                    description: RetryAfter is the timestamp this cert request is
                      not retried before.
                    format: date-time
                    type: string
                  recheckInterval:
                    description: RetryInterval is interval to wait for retrying.
                    type: string
                required:
                - recheckAfter
                - recheckInterval
                type: object
              commonName:
                description: CommonName is the current CN.
                type: string
              conditions:
                description: List of status conditions to indicate the status of certificates.
                  Known condition types are ` + "`" + `Ready` + "`" + `.
                items:
                  description: "Condition contains details for one aspect of the current
                    state of this API Resource. --- This struct is intended for direct
                    use as an array at the field path .status.conditions.  For example,
                    \n type FooStatus struct{ // Represents the observations of a
                    foo's current state. // Known .status.conditions.type are: \"Available\",
                    \"Progressing\", and \"Degraded\" // +patchMergeKey=type // +patchStrategy=merge
                    // +listType=map // +listMapKey=type Conditions []metav1.Condition
                    ` + "`" + `json:\"conditions,omitempty\" patchStrategy:\"merge\" patchMergeKey:\"type\"
                    protobuf:\"bytes,1,rep,name=conditions\"` + "`" + ` \n // other fields }"
                  properties:
                    lastTransitionTime:
                      description: lastTransitionTime is the last time the condition
                        transitioned from one status to another. This should be when
                        the underlying condition changed.  If that is not known, then
                        using the time when the API field changed is acceptable.
                      format: date-time
                      type: string
                    message:
                      description: message is a human readable message indicating
                        details about the transition. This may be an empty string.
                      maxLength: 32768
                      type: string
                    observedGeneration:
                      description: observedGeneration represents the .metadata.generation
                        that the condition was set based upon. For instance, if .metadata.generation
                        is currently 12, but the .status.conditions[x].observedGeneration
                        is 9, the condition is out of date with respect to the current
                        state of the instance.
                      format: int64
                      minimum: 0
                      type: integer
                    reason:
                      description: reason contains a programmatic identifier indicating
                        the reason for the condition's last transition. Producers
                        of specific condition types may define expected values and
                        meanings for this field, and whether the values are considered
                        a guaranteed API. The value should be a CamelCase string.
                        This field may not be empty.
                      maxLength: 1024
                      minLength: 1
                      pattern: ^[A-Za-z]([A-Za-z0-9_,:]*[A-Za-z0-9_])?$
                      type: string
                    status:
                      description: status of the condition, one of True, False, Unknown.
                      enum:
                      - "True"
                      - "False"
                      - Unknown
                      type: string
                    type:
                      description: type of condition in CamelCase or in foo.example.com/CamelCase.
                        --- Many .condition.type values are consistent across resources
                        like Available, but because arbitrary conditions can be useful
                        (see .node.status.conditions), the ability to deconflict is
                        important. The regex it matches is (dns1123SubdomainFmt/)?(qualifiedNameFmt)
                      maxLength: 316
                      pattern: ^([a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*/)?(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])$
                      type: string
                  required:
                  - lastTransitionTime
                  - message
                  - reason
                  - status
                  - type
                  type: object
                type: array
              dnsNames:
                description: DNSNames are the current domain names.
                items:
                  type: string
                type: array
              expirationDate:
                description: ExpirationDate shows the notAfter validity date.
                type: string
              issuerRef:
                description: IssuerRef is the used issuer.
                properties:
                  cluster:
                    description: Cluster is the cluster name of the issuer ('default'
                      or 'target'). optional because of backwards compatibility
                    type: string
                  name:
                    description: Name is the name of the issuer.
                    type: string
                  namespace:
                    description: Namespace is the namespace of the issuer.
                    type: string
                required:
                - name
                - namespace
                type: object
              lastPendingTimestamp:
                description: LastPendingTimestamp contains the start timestamp of
                  the last pending status.
                format: date-time
                type: string
              message:
                description: Message is the status or error message.
                type: string
              observedGeneration:
                description: ObservedGeneration is the observed generation of the
                  spec.
                format: int64
                type: integer
              state:
                description: State is the certificate state.
                type: string
            required:
            - state
            type: object
        required:
        - spec
        type: object
    served: true
    storage: true
    subresources:
      status: {}
  `
	utils.Must(registry.RegisterCRD(data))
	data = `
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    controller-gen.kubebuilder.io/version: v0.13.0
  name: issuers.cert.gardener.cloud
spec:
  group: cert.gardener.cloud
  names:
    kind: Issuer
    listKind: IssuerList
    plural: issuers
    singular: issuer
  scope: Namespaced
  versions:
  - additionalPrinterColumns:
    - description: ACME Server
      jsonPath: .spec.acme.server
      name: SERVER
      type: string
    - description: ACME Registration email
      jsonPath: .spec.acme.email
      name: EMAIL
      type: string
    - description: Status of registration
      jsonPath: .status.state
      name: STATUS
      type: string
    - description: Issuer type
      jsonPath: .status.type
      name: TYPE
      type: string
    - description: object creation timestamp
      jsonPath: .metadata.creationTimestamp
      name: AGE
      type: date
    - description: included domains
      jsonPath: .spec.acme.domains.include
      name: INCLUDED_DOMAINS
      priority: 2000
      type: string
    name: v1alpha1
    schema:
      openAPIV3Schema:
        description: Issuer is the issuer CR.
        properties:
          apiVersion:
            description: 'APIVersion defines the versioned schema of this representation
              of an object. Servers should convert recognized schemas to the latest
              internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources'
            type: string
          kind:
            description: 'Kind is a string value representing the REST resource this
              object represents. Servers may infer this from the endpoint the client
              submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds'
            type: string
          metadata:
            type: object
          spec:
            description: IssuerSpec is the spec of the issuer.
            properties:
              acme:
                description: ACME is the ACME protocol specific spec.
                properties:
                  autoRegistration:
                    description: AutoRegistration is the flag if automatic registration
                      should be applied if needed.
                    type: boolean
                  domains:
                    description: Domains optionally specifies domains allowed or forbidden
                      for certificate requests
                    properties:
                      exclude:
                        description: Exclude are domain names for which certificate
                          requests are forbidden (including any subdomains)
                        items:
                          type: string
                        type: array
                      include:
                        description: Include are domain names for which certificate
                          requests are allowed (including any subdomains)
                        items:
                          type: string
                        type: array
                    type: object
                  email:
                    description: Email is the email address to use for user registration.
                    type: string
                  externalAccountBinding:
                    description: ACMEExternalAccountBinding is a reference to a CA
                      external account of the ACME server.
                    properties:
                      keyID:
                        description: keyID is the ID of the CA key that the External
                          Account is bound to.
                        type: string
                      keySecretRef:
                        description: keySecretRef is the secret ref to the Secret
                          which holds the symmetric MAC key of the External Account
                          Binding with data key 'hmacKey'. The secret key stored in
                          the Secret **must** be un-padded, base64 URL encoded data.
                        properties:
                          name:
                            description: name is unique within a namespace to reference
                              a secret resource.
                            type: string
                          namespace:
                            description: namespace defines the space within which
                              the secret name must be unique.
                            type: string
                        type: object
                        x-kubernetes-map-type: atomic
                    required:
                    - keyID
                    - keySecretRef
                    type: object
                  precheckNameservers:
                    description: PrecheckNameservers overwrites the default precheck
                      nameservers used for checking DNS propagation. Format ` + "`" + `host` + "`" + `
                      or ` + "`" + `host:port` + "`" + `, e.g. "8.8.8.8" same as "8.8.8.8:53" or "google-public-dns-a.google.com:53".
                    items:
                      type: string
                    type: array
                  privateKeySecretRef:
                    description: PrivateKeySecretRef is the secret ref to the ACME
                      private key.
                    properties:
                      name:
                        description: name is unique within a namespace to reference
                          a secret resource.
                        type: string
                      namespace:
                        description: namespace defines the space within which the
                          secret name must be unique.
                        type: string
                    type: object
                    x-kubernetes-map-type: atomic
                  server:
                    description: Server is the URL of the ACME server.
                    type: string
                  skipDNSChallengeValidation:
                    description: SkipDNSChallengeValidation marks that this issuer
                      does not validate DNS challenges. In this case no DNS entries/records
                      are created for a DNS Challenge and DNS propagation is not checked.
                    type: boolean
                required:
                - email
                - server
                type: object
              ca:
                description: CA is the CA specific spec.
                properties:
                  privateKeySecretRef:
                    description: PrivateKeySecretRef is the secret ref to the CA secret.
                    properties:
                      name:
                        description: name is unique within a namespace to reference
                          a secret resource.
                        type: string
                      namespace:
                        description: namespace defines the space within which the
                          secret name must be unique.
                        type: string
                    type: object
                    x-kubernetes-map-type: atomic
                type: object
              requestsPerDayQuota:
                description: RequestsPerDayQuota is the maximum number of certificate
                  requests per days allowed for this issuer
                type: integer
            type: object
          status:
            description: IssuerStatus is the status of the issuer.
            properties:
              acme:
                description: ACME is the ACME specific status.
                type: object
                x-kubernetes-preserve-unknown-fields: true
              ca:
                description: CA is the CA specific status.
                type: object
                x-kubernetes-preserve-unknown-fields: true
              message:
                description: Message is the status or error message.
                type: string
              observedGeneration:
                description: ObservedGeneration is the observed generation of the
                  spec.
                format: int64
                type: integer
              requestsPerDayQuota:
                description: RequestsPerDayQuota is the actual maximum number of certificate
                  requests per days allowed for this issuer
                type: integer
              state:
                description: State is either empty, 'Pending', 'Error', or 'Ready'.
                type: string
              type:
                description: Type is the issuer type. Currently only 'acme' and 'ca'
                  are supported.
                type: string
            required:
            - state
            type: object
        required:
        - spec
        type: object
    served: true
    storage: true
    subresources:
      status: {}
  `
	utils.Must(registry.RegisterCRD(data))
}

func AddToRegistry(r apiextensions.Registry) {
	registry.AddToRegistry(r)
}

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
    controller-gen.kubebuilder.io/version: v0.4.1
  creationTimestamp: null
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
    - description: if true certificate objects should be renewed before revoking old certificates certificate(s)
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
            description: 'APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources'
            type: string
          kind:
            description: 'Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds'
            type: string
          metadata:
            type: object
          spec:
            description: CertificateRevocationSpec is the spec of the certificate revocation.
            properties:
              certificateRef:
                description: CertificateRef is the references to the certificate to be revoked
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
                description: QualifyingDate specifies that any certificate with the same DNS names like the given 'certificateRef' should be revoked if it is valid before this date. If not specified, it will be filled with the current time.
                format: date-time
                type: string
              renew:
                description: Renew specifies if certificate objects should be renewed before revoking old certificates
                type: boolean
            type: object
          status:
            description: CertificateRevocationStatus is the status of the certificate request.
            properties:
              message:
                description: Message is the status or error message.
                type: string
              objects:
                description: ObjectStatuses contains the statuses of the involved certificate objects
                properties:
                  failed:
                    description: Failed is the list of certificate objects whose processing failed
                    items:
                      description: CertificateRef is the reference of the issuer by name.
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
                    type: array
                  processing:
                    description: Processing is the list of certificate objects to be processed
                    items:
                      description: CertificateRef is the reference of the issuer by name.
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
                    type: array
                  renewed:
                    description: Renewed is the list of certificate objects successfully renewed
                    items:
                      description: CertificateRef is the reference of the issuer by name.
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
                    type: array
                  revoked:
                    description: Revoked is the list of certificate objects successfully revoked (without renewal)
                    items:
                      description: CertificateRef is the reference of the issuer by name.
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
                    type: array
                type: object
              observedGeneration:
                description: ObservedGeneration is the observed generation of the spec.
                format: int64
                type: integer
              revocationApplied:
                description: RevocationApplied is the timestamp when the revocation was completed
                format: date-time
                type: string
              secrets:
                description: SecretStatuses contains the statuses of the involved certificate secrets
                properties:
                  failed:
                    description: Failed is the list of certificate secrets whose revocation failed
                    items:
                      description: CertificateSecretRef is a reference to a secret together with the serial number
                      properties:
                        name:
                          description: Name is unique within a namespace to reference a secret resource.
                          type: string
                        namespace:
                          description: Namespace defines the space within which the secret name must be unique.
                          type: string
                        serialNumber:
                          description: SerialNumber is the serial number of the certificate
                          type: string
                      required:
                      - serialNumber
                      type: object
                    type: array
                  processing:
                    description: Processing is the list of certificate secrets to be processed
                    items:
                      description: CertificateSecretRef is a reference to a secret together with the serial number
                      properties:
                        name:
                          description: Name is unique within a namespace to reference a secret resource.
                          type: string
                        namespace:
                          description: Namespace defines the space within which the secret name must be unique.
                          type: string
                        serialNumber:
                          description: SerialNumber is the serial number of the certificate
                          type: string
                      required:
                      - serialNumber
                      type: object
                    type: array
                  revoked:
                    description: Revoked is the list of certificate secrets successfully revoked
                    items:
                      description: CertificateSecretRef is a reference to a secret together with the serial number
                      properties:
                        name:
                          description: Name is unique within a namespace to reference a secret resource.
                          type: string
                        namespace:
                          description: Namespace defines the space within which the secret name must be unique.
                          type: string
                        serialNumber:
                          description: SerialNumber is the serial number of the certificate
                          type: string
                      required:
                      - serialNumber
                      type: object
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
status:
  acceptedNames:
    kind: ""
    plural: ""
  conditions: []
  storedVersions: []
  `
	utils.Must(registry.RegisterCRD(data))
	data = `

---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    controller-gen.kubebuilder.io/version: v0.4.1
  creationTimestamp: null
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
            description: 'APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources'
            type: string
          kind:
            description: 'Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds'
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
                description: CSR is the alternative way to provide CN,DNSNames and other information.
                format: byte
                type: string
              dnsNames:
                description: DNSNames are the optional additional domain names of the certificate.
                items:
                  type: string
                type: array
              ensureRenewedAfter:
                description: EnsureRenewedAfter specifies a time stamp in the past. Renewing is only triggered if certificate notBefore date is before this date.
                format: date-time
                type: string
              issuerRef:
                description: IssuerRef is the reference of the issuer to use.
                properties:
                  name:
                    description: Name is the name of the issuer CR (in the configured issuer namespace).
                    type: string
                required:
                - name
                type: object
              renew:
                description: Renew triggers a renewal if set to true
                type: boolean
              secretName:
                description: SecretName is the name of the secret object to use for storing the certificate.
                type: string
              secretRef:
                description: SecretRef is the reference of the secret object to use for storing the certificate.
                properties:
                  name:
                    description: Name is unique within a namespace to reference a secret resource.
                    type: string
                  namespace:
                    description: Namespace defines the space within which the secret name must be unique.
                    type: string
                type: object
            type: object
          status:
            description: CertificateStatus is the status of the certificate request.
            properties:
              backoff:
                description: BackOff contains the state to back off failed certificate requests
                properties:
                  observedGeneration:
                    description: ObservedGeneration is the observed generation the BackOffState is assigned to
                    format: int64
                    type: integer
                  recheckAfter:
                    description: RetryAfter is the timestamp this cert request is not retried before.
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
                  name:
                    description: Name is the name of the issuer CR.
                    type: string
                  namespace:
                    description: Namespace is the namespace of the issuer CR.
                    type: string
                required:
                - name
                - namespace
                type: object
              lastPendingTimestamp:
                description: LastPendingTimestamp contains the start timestamp of the last pending status.
                format: date-time
                type: string
              message:
                description: Message is the status or error message.
                type: string
              observedGeneration:
                description: ObservedGeneration is the observed generation of the spec.
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
status:
  acceptedNames:
    kind: ""
    plural: ""
  conditions: []
  storedVersions: []
  `
	utils.Must(registry.RegisterCRD(data))
	data = `

---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    controller-gen.kubebuilder.io/version: v0.4.1
  creationTimestamp: null
  name: issuers.cert.gardener.cloud
spec:
  group: cert.gardener.cloud
  names:
    kind: Issuer
    listKind: IssuerList
    plural: issuers
    shortNames:
    - issuer
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
            description: 'APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources'
            type: string
          kind:
            description: 'Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds'
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
                    description: AutoRegistration is the flag if automatic registration should be applied if needed.
                    type: boolean
                  domains:
                    description: Domains optionally specifies domains allowed or forbidden for certificate requests
                    properties:
                      exclude:
                        description: Exclude are domain names for which certificate requests are forbidden (including any subdomains)
                        items:
                          type: string
                        type: array
                      include:
                        description: Include are domain names for which certificate requests are allowed (including any subdomains)
                        items:
                          type: string
                        type: array
                    type: object
                  email:
                    description: Email is the email address to use for user registration.
                    type: string
                  externalAccountBinding:
                    description: ACMEExternalAccountBinding is a reference to a CA external account of the ACME server.
                    properties:
                      keyID:
                        description: keyID is the ID of the CA key that the External Account is bound to.
                        type: string
                      keySecretRef:
                        description: keySecretRef is the secret ref to the Secret which holds the symmetric MAC key of the External Account Binding with data key 'hmacKey'. The secret key stored in the Secret **must** be un-padded, base64 URL encoded data.
                        properties:
                          name:
                            description: Name is unique within a namespace to reference a secret resource.
                            type: string
                          namespace:
                            description: Namespace defines the space within which the secret name must be unique.
                            type: string
                        type: object
                    required:
                    - keyID
                    - keySecretRef
                    type: object
                  privateKeySecretRef:
                    description: PrivateKeySecretRef is the secret ref to the ACME private key.
                    properties:
                      name:
                        description: Name is unique within a namespace to reference a secret resource.
                        type: string
                      namespace:
                        description: Namespace defines the space within which the secret name must be unique.
                        type: string
                    type: object
                  server:
                    description: Server is the URL of the ACME server.
                    type: string
                  skipDNSChallengeValidation:
                    description: SkipDNSChallengeValidation marks that this issuer does not validate DNS challenges. In this case no DNS entries/records are created for a DNS Challenge and DNS propagation is not checked.
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
                        description: Name is unique within a namespace to reference a secret resource.
                        type: string
                      namespace:
                        description: Namespace defines the space within which the secret name must be unique.
                        type: string
                    type: object
                type: object
              requestsPerDayQuota:
                description: RequestsPerDayQuota is the maximum number of certificate requests per days allowed for this issuer
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
                description: ObservedGeneration is the observed generation of the spec.
                format: int64
                type: integer
              requestsPerDayQuota:
                description: RequestsPerDayQuota is the actual maximum number of certificate requests per days allowed for this issuer
                type: integer
              state:
                description: State is either empty, 'Pending', 'Error', or 'Ready'.
                type: string
              type:
                description: Type is the issuer type. Currently only 'acme' and 'ca' are supported.
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
status:
  acceptedNames:
    kind: ""
    plural: ""
  conditions: []
  storedVersions: []
  `
	utils.Must(registry.RegisterCRD(data))
}

func AddToRegistry(r apiextensions.Registry) {
	registry.AddToRegistry(r)
}

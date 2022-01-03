# Certificate Management

[![reuse compliant](https://reuse.software/badge/reuse-compliant.svg)](https://reuse.software/)

The cert-manager manages TLS certificates in Kubernetes clusters using custom resources.

In a multi-cluster environment like Gardener, using existing open source projects
for certificate management like [cert-manager](https://github.com/jetstack/cert-manager) becomes cumbersome.
With this project the separation of concerns between multiple clusters is realized more easily.
The cert-controller-manager runs in a **secured cluster** where the issuer secrets are stored.
At the same time it watches an untrusted **source cluster** and can provide certificates for it.
The cert-controller-manager relies on DNS challenges (ACME only) for validating the domain names of the certificates.
For this purpose it creates DNSEntry custom resources (in a possible separate **dns cluster**) to be
handled by the compagnion dns-controller-manager from [external-dns-management](https://github.com/gardener/external-dns-management).

Currently, the `cert-controller-manager` supports certificate authorities via:

* [Automatic Certificate Management Environment (ACME)](https://en.wikipedia.org/wiki/Automated_Certificate_Management_Environment) protocol like [Let's Encrypt](https://letsencrypt.org/).
* Certificate Authority (CA): an existing certificate and a private key provided as a TLS Secret.

**Index**
  - [Quick start using certificates in a Gardener shoot cluster](#quick-start-using-certificates-in-a-gardener-shoot-cluster)
  - [Setting up Issuers](#setting-up-issuers)
    - [Automatic Certificate Management Environment (ACME)](#automatic-certificate-management-environment-acme)
      - [Auto registration](#auto-registration)
      - [Using existing account](#using-existing-account)
    - [Certificate Authority (CA)](#certificate-authority-ca)
  - [Requesting a Certificate](#requesting-a-certificate)
    - [Using `commonName` and optional `dnsNames`](#using-commonname-and-optional-dnsnames)
    - [Using a certificate signing request (CSR)](#using-a-certificate-signing-request-csr)
  - [Requesting a Certificate for Ingress](#requesting-a-certificate-for-ingress)
    - [Process](#process)
  - [Requesting a Certificate for Service](#requesting-a-certificate-for-service)
  - [Demo quick start](#demo-quick-start)
  - [Using the cert-controller-manager](#using-the-cert-controller-manager)
    - [Usage](#usage)
  - [Renewal of Certificates](#renewal-of-certificates)
  - [Revoking Certificates](#revoking-certificates)
    - [Revoking certificates with renewal](#revoking-certificates-with-renewal)
    - [Checking OCSP revocation using OpenSSL](#checking-ocsp-revocation-using-openssl)
  - [Metrics](#metrics)
  - [Development](#development)

## Quick start using certificates in a Gardener shoot cluster

This component is typically deployed by the [Gardener Extension for certificate services](https://github.com/gardener/gardener-extension-shoot-cert-service/blob/master/docs/installation/setup.md)
to simplify requesting certificates for Gardener shoot clusters.

For a quick start please see [Request X.509 Certificates](https://gardener.cloud/docs/guides/administer_shoots/request_cert/)

## Setting up Issuers

Before you can obtain certificates from a certificate authority (CA), you need to set up an issuer.
The issuer is specified in the `default` cluster, while the certificates are specified in the `source` cluster.

The issuer custom resource contains the configuration and registration data for your account at the CA.

### Automatic Certificate Management Environment (ACME)

Two modes are supported:

- auto registration
- using an existing account

#### Auto registration

Auto registration is mainly used for development and test environments. You only need to provide
the server URL and an email address. The registration process is done automatically for you
by creating a private key and performing the registration at the CA. Optionally you can provide
the target secret with the privateKeySecretRef section.

For example see [examples/20-issuer-staging.yaml](./examples/20-issuer-staging.yaml):

```yaml
apiVersion: cert.gardener.cloud/v1alpha1
kind: Issuer
metadata:
  name: issuer-staging
  namespace: default
spec:
  acme:
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    email: some.user@mydomain.com
    autoRegistration: true
    # with 'autoRegistration: true' a new account will be created if the secretRef is not existing
    privateKeySecretRef:
      name: issuer-staging-secret
      namespace: default
```

#### Using existing account

If you already have an existing account at the certificate authority, you need to
specify email address and reference the private key from a secret.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-issuer-secret
  namespace: default
type: Opaque
data:
  privateKey: LS0tLS1...
```

```yaml
apiVersion: cert.gardener.cloud/v1alpha1
kind: Issuer
metadata:
  name: my-issuer
  namespace: default
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: my.account@mydomain.com
    privateKeySecretRef:
      name: my-issuer-secret
      namespace: default
```

In both cases, the state of an issuer resource can be checked on the `default` cluster with

```bash
▶ kubectl get issuer
NAME             SERVER                                                   EMAIL                    STATUS   TYPE   AGE
issuer-staging   https://acme-staging-v02.api.letsencrypt.org/directory   some.user@mydomain.com   Ready    acme   8s
```

### Certificate Authority (CA)

This issuer is meant to be used where a central Certificate Authority
is already in place. The operator must request/provide by its own means a CA
or an intermediate CA. This is mainly used for **on-premises** and
**airgapped** environements.

It can also be used for **developement** or **testing** purproses. In this case
a Self-signed Certificate Authority can be created by following the section below.

_Create a Self-signed Certificate Authority (optional)_

```bash
▶ openssl genrsa -out CA-key.pem 4096
▶ export CONFIG="
[req]
distinguished_name=dn
[ dn ]
[ ext ]
basicConstraints=CA:TRUE,pathlen:0
"
▶ openssl req \
    -new -nodes -x509 -config <(echo "$CONFIG") -key CA-key.pem \
    -subj "/CN=Hello" -extensions ext -days 1000 -out CA-cert.pem
```

Create a TLS secret from the certificate `CA-cert.pem` and the private key `CA-key.pem`

```bash
▶ kubectl -n default create secret tls issuer-ca-secret \
    --cert=CA-cert.pem --key=CA-key.pem -oyaml \
    --dry-run=client > secret.yaml
```

The content of the `secret.yaml` should look like the following, for a full example see [examples/20-issuer-ca.yaml](./examples/20-issuer-ca.yaml)

```yaml
apiVersion: v1
data:
  tls.crt: {base64 certificate}
  tls.key: {base64 private key}
kind: Secret
metadata:
  name: issuer-ca-secret
type: kubernetes.io/tls
```

Apply the secrets in the cluster and create the issuer,
for example see [examples/20-issuer-ca.yaml](./examples/20-issuer-ca.yaml)

```yaml
---
apiVersion: cert.gardener.cloud/v1alpha1
kind: Issuer
metadata:
  name: issuer-ca
  namespace: default
spec:
  ca:
    privateKeySecretRef:
      name: issuer-ca-secret
      namespace: default
```

The state of the issuer resource can be checked on the `default` cluster with

```bash
▶ kubectl get issuer
NAME        SERVER   EMAIL   STATUS   TYPE   AGE
issuer-ca                    Ready    ca     6s
```

Some details about the CA can be found in the status of the issuer.

```bash
▶ kubectl get issuer issuer-ca -ojsonpath='{.status}' | jq '.'
{
  "ca": {
    "NotAfter": "2023-05-31T14:55:55Z",
    "NotBefore": "2020-09-03T14:55:55Z",
    "Subject": {
      "CommonName": "my-domain.com",
      "Country": [
        "DE"
      ],
      "Locality": [
        "Walldorf"
      ],
      "Organization": [
        "Gardener"
      ],
      "OrganizationalUnit": [
        "Gardener"
      ],
      "PostalCode": null,
      "Province": [
        "BW"
      ],
      "SerialNumber": "1E04A2C8F057AC890F45FEC5446AE4DDA73EA1D5",
      "StreetAddress": null
    }
  },
  "observedGeneration": 1,
  "requestsPerDayQuota": 10000,
  "state": "Ready",
  "type": "ca"
}
```

## Requesting a Certificate

To obtain a certificate for a domain, you specify a certificate custom resource on the `source` cluster.
You can specify the issuer explicitly by reference. If there is no issuer reference, the default issuer is
used (provided as command line option). You must either specify the `commonName` and further optional `dnsNames` or
you can also start with a certificate signing request (CSR).

For domain validation, the `cert-controller-manager` only supports DNS challenges. For this purpose it relies
on the `dns-controller-manager` from the [external-dns-management](https://github.com/gardener/external-dns-management)
project.
If any domain name (`commonName` or any item from `dnsNames`) needs to be validated, it creates a custom resource
`DNSEntry` in the `dns` cluster.
When the certificate authority sees the temporary DNS record, the certificate is stored in a secret finally.
The name of the secret can be specified explicitly with `secretName` and will be stored in the same namespace as the 
certificate on the `source` cluster.

The certificate is checked for renewal periodically. The renewal is performed automatically and the secret is updated.
Default values for periodical check is daily, the certificate is renewed if its validity expires within 60 days.

### Using `commonName` and optional `dnsNames`

For example see [examples/30-cert-simple.yaml](./examples/30-cert-simple.yaml):

```yaml
apiVersion: cert.gardener.cloud/v1alpha1
kind: Certificate
metadata:
  name: cert-simple
  namespace: default
spec:
  commonName: cert1.mydomain.com
  dnsNames:
  - cert1-foo.mydomain.com
  - cert1-bar.mydomain.com
  # if issuer is not specified, the default issuer is used
  issuerRef:
    name: issuer-staging
```

### Using a certificate signing request (CSR)

You can provide a complete CSR in PEM format (and encoded as Base64).

For example see [examples/30-cert-csr.yaml](./examples/30-cert-csr.yaml):

```yaml
apiVersion: cert.gardener.cloud/v1alpha1
kind: Certificate
metadata:
  name: cert-csr
  namespace: default
spec:
  csr: LS0tLS1CRUd...
  issuerRef:
    name: issuer-staging
```

:warning: Using a CSR is only available for ACME Issuer

## Requesting a Certificate for Ingress 

Add the annotation `cert.gardener.cloud/purpose: managed` to the Ingress resource.
The `cert-controller-manager` will then automatically request a certificate for all domains given by the hosts in the
`tls` section of the Ingress spec.

For compatibility with the [Gardener Cert-Broker](https://github.com/gardener/cert-broker), you can
alternatively use the deprecated label `garden.sapcloud.io/purpose: managed-cert` for the same outcome.

See also [examples/40-ingress-echoheaders.yaml](./examples/40-ingress-echoheaders.yaml):

### Process

1. Create the Ingress Resource (optional)

    In order to request a certificate for a domain managed by `cert-controller-manager` an Ingress is required.
    In case you don’t already have one, take the following as an example:

    ```yaml
    apiVersion: networking.k8s.io/v1
    kind: Ingress
    metadata:
      name: vuejs-ingress
    spec:
      tls:
      # Gardener managed default domain.
      # The first host is used as common name and must not exceed 64 characters
      - hosts:
        - test.ingress.<GARDENER-CLUSTER>.<GARDENER-PROJECT>.shoot.example.com
        # Certificate and private key reside in this secret.
        secretName: testsecret-tls
      rules:
      - host: test.ingress.<GARDENER-CLUSTER>.<GARDENER-PROJECT>.shoot.example.com
        http:
          paths:
          - backend:
              service:
                name: vuejs-svc
                port:
                  number: 8080
            path: /
            pathType: Prefix
    ```

2. Annotate the Ingress Resource

   The annotation `cert.gardener.cloud/purpose: managed` instructs `cert-controller-manager` to handle certificate issuance for the domains found in labeled Ingress.

    ```yaml
    apiVersion: networking.k8s.io/v1
    kind: Ingress
    metadata:
      name: tls-example-ingress
      annotations:
        # Let Gardener manage certificates for this Ingress.
        cert.gardener.cloud/purpose: managed
        #dns.gardener.cloud/class: garden # needed on Gardener shoot clusters for managed DNS record creation (if not covered by `*.ingress.<GARDENER-CLUSTER>.<GARDENER-PROJECT>.shoot.example.com)
        #cert.gardener.cloud/commonname: "*.demo.mydomain.com" # optional, if not specified the first name from spec.tls[].hosts is used as common name
        #cert.gardener.cloud/dnsnames: "" # optional, if not specified the names from spec.tls[].hosts are used
    spec:
      tls:
        - hosts:
            - echoheaders.demo.mydomain.com
          secretName: cert-echoheaders
      rules:
        - host: echoheaders.demo.mydomain.com
          http:
            paths:
              - backend:
                  service:
                    name: echoheaders
                    port:
                      number: 80
                path: /
                pathType: Prefix
    ```
  
    The annotation `cert.gardener.cloud/commonname` can be set to explicitly specify the common name.
    If no set, the first name of `spec.tls.hosts` is used as common name.
    The annotation `cert.gardener.cloud/dnsnames` can be used to explicitly specify the alternative DNS names.
    If no set, the names of `spec.tls.hosts` are used.

3. Check status

   A `certificate` custom resource is created in the same namespace of the `source` cluster.
   You can either check the status of this certificate resource with `kubectl get cert` or you can check
   the events for the ingress with `kubectl get events`

   The certificate is stored in the secret as specified in the Ingress resource.

## Requesting a Certificate for Service 

If you have a service of type `LoadBalancer`, you can use the annotation `cert.gardener.cloud/secretname` together
with the annotation `dns.gardener.cloud/dnsnames` from the `dns-controller-manager` to trigger automatic creation of 
a certificate. If you wan to share a certificate between multiple services and ingresses, using the annotations 
`cert.gardener.cloud/commonname` and `cert.gardener.cloud/dnsnames` may be helpful.

```yaml
apiVersion: v1
kind: Service
metadata:
  annotations:
    cert.gardener.cloud/secretname: test-service-secret
    dns.gardener.cloud/dnsnames: test-service.demo.mydomain.com
    #dns.gardener.cloud/class: garden # needed on Gardener shoot clusters for managed DNS record creation
    #cert.gardener.cloud/commonname: "*.demo.mydomain.com" # optional, if not specified the first name from dns.gardener.cloud/dnsnames is used as common name
    #cert.gardener.cloud/dnsnames: "" # optional, if specified overrides dns.gardener.cloud/dnsnames annotation for certificate names
    dns.gardener.cloud/ttl: "600"
  name: test-service
  namespace: default
spec:
  ports:
  - name: http
    port: 80
    protocol: TCP
    targetPort: 8080
  type: LoadBalancer
```

The annotation `cert.gardener.cloud/commonname` is optional. If not specified, the first name of the annotation
`dns.gardener.cloud/dnsnames` is used as common name. It is useful to specify it explicitly, if no `DNSEntry`
should be created for the common name by the dns-controller-manager.
A typical use case is if the common name (limited to 64 characters) is set only to
deal with real domain names specified with `dns.gardener.cloud/dnsnames` which are longer than 64 characters.
The annotation `cert.gardener.cloud/dnsnames` can be used to explicitly specify the alternative DNS names.
If set, it overrides the values from the annotation `dns.gardener.cloud/dnsnames` for the certificate (but not for 
creating DNS records by the dns-controller-manager).

If you want to share a certificate between multiple services and ingresses, using the annotations `cert.gardener.cloud/commonname` and
`cert.gardener.cloud/dnsnames` may be helpful. For example, to share a wildcard certificate, you should add these two annotations

```yaml
    cert.gardener.cloud/commonname: "*.demo.mydomain.com"
    cert.gardener.cloud/dnsnames: ""
```
This will create or reuse a certificate for `*.demo.mydomain.com`. An existing certificate is automatically reused,
if it has exactly the same common name and DNS names.

## Demo quick start

1. Run dns-controller-manager with:

    ```bash
    ./dns-controller-manager --controllers=azure-dns --identifier=myOwnerId --disable-namespace-restriction
    ```

2. Ensure provider and its secret, e.g.

    ```bash
    kubectl apply -f azure-secret.yaml
    kubectl apply -f azure-provider.yaml
    ```

   - check with

        ```bash
        ▶ kubectl get dnspr
        NAME               TYPE        STATUS   AGE
        azure-playground   azure-dns   Ready    28m
        ```

3. Create test namespace

    ```bash
    kubectl create ns test
    ```

4. Run cert-controller-manager

    ```bash
    ./cert-controller-manager
    ```

5. Register user `some.user@mydomain.com` at let's encrypt

    ```bash
    kubectl apply -f examples/20-issuer-staging.yaml
    ```

   - check with

        ```bash
        ▶ kubectl get issuer
        NAME             SERVER                                                   EMAIL                    STATUS   TYPE   AGE
        issuer-staging   https://acme-staging-v02.api.letsencrypt.org/directory   some.user@mydomain.com   Ready    acme   8s
        ```

6. Request a certificate for `cert1.martin.test6227.ml`

    ```bash
    kubectl apply -f examples/30-cert-simple.yaml
    ```

    If this certificate has been already registered for the same issuer before,
    it will be returned immediately from the ACME server.
    Otherwise a DNS challenge is started using a temporary DNSEntry to be set by `dns-controller-manager`

   - check with

        ```bash
        ▶ kubectl get cert -o wide
        NAME          COMMON NAME           ISSUER           STATUS   EXPIRATION_DATE        DNS_NAMES                 AGE
        cert-simple   cert1.mydomain.com    issuer-staging   Ready    2019-11-10T09:48:17Z   [cert1.my-domain.com]     34s
        ```

## Using the cert-controller-manager

The cert-controller-manager communicated with up to four different clusters:
- **default** 
  used for managing issuers and lease management.
  The path to the kubeconfig is specified with command line option `--kubeconfig`.
- **source**
  used for watching resources ingresses, services and certificates
  The path to the kubeconfig is specified with command line option `--source`.
  If option is omitted, the default cluster is used for source.
- **dns**
  used to write temporary DNSEntries for DNS challenges
  The path to the kubeconfig is specified with command line option `--dns`.
  If option is omitted, the default cluster is used for dns.
- **target**
  used for storing generated certificates (and issuers if `--allow-target-issuers` 
  option is set)
  The path to the kubeconfig is specified with command line option `--target`.
  If option is omitted, the source cluster is also used for target.

### Usage
The complete list of options is:

```text
Usage:
  cert-controller-manager [flags]

Flags:
      --accepted-maintainers string                        accepted maintainer key(s) for crds
      --acme-deactivate-authorizations                     if true authorizations are always deactivated after each ACME certificate request
      --allow-target-issuers                               If true, issuers are also watched on the target cluster
      --bind-address-http string                           HTTP server bind address
      --cascade-delete                                     If true, certificate secrets are deleted if dependent resources (certificate, ingress) are deleted
      --cert-class string                                  Identifier used to differentiate responsible controllers for entries
      --cert-target-class string                           Identifier used to differentiate responsible dns controllers for target entries
      --config string                                      config file
  -c, --controllers string                                 comma separated list of controllers to start (<name>,<group>,all)
      --cpuprofile string                                  set file for cpu profiling
      --default-issuer string                              name of default issuer (from default cluster)
      --default-issuer-domain-ranges string                domain range restrictions when using default issuer separated by comma
      --default-requests-per-day-quota int                 Default value for requestsPerDayQuota if not set explicitly in the issuer spec.
      --default.pool.resync-period duration                Period for resynchronization for pool default
      --default.pool.size int                              Worker pool size for pool default
      --disable-namespace-restriction                      disable access restriction for namespace local access only
      --dns string                                         cluster for writing challenge DNS entries
      --dns-class string                                   class for creating challenge DNSEntries (in DNS cluster)
      --dns-namespace string                               namespace for creating challenge DNSEntries (in DNS cluster)
      --dns-owner-id string                                ownerId for creating challenge DNSEntries
      --dns.disable-deploy-crds                            disable deployment of required crds for cluster dns
      --dns.id string                                      id for cluster dns
      --dns.migration-ids string                           migration id for cluster dns
      --force-crd-update                                   enforce update of crds even they are unmanaged
      --grace-period duration                              inactivity grace period for detecting end of cleanup for shutdown
  -h, --help                                               help for cert-controller-manager
      --ingress-cert.cert-class string                     Identifier used to differentiate responsible controllers for entries of controller ingress-cert
      --ingress-cert.cert-target-class string              Identifier used to differentiate responsible dns controllers for target entries of controller ingress-cert
      --ingress-cert.default.pool.resync-period duration   Period for resynchronization for pool default of controller ingress-cert
      --ingress-cert.default.pool.size int                 Worker pool size for pool default of controller ingress-cert
      --ingress-cert.pool.resync-period duration           Period for resynchronization of controller ingress-cert
      --ingress-cert.pool.size int                         Worker pool size of controller ingress-cert
      --ingress-cert.target-name-prefix string             name prefix in target namespace for cross cluster generation of controller ingress-cert
      --ingress-cert.target-namespace string               target namespace for cross cluster generation of controller ingress-cert
      --ingress-cert.targets.pool.size int                 Worker pool size for pool targets of controller ingress-cert
      --issuer-namespace string                            namespace to lookup issuers on default cluster
      --issuer.acme-deactivate-authorizations              if true authorizations are always deactivated after each ACME certificate request of controller issuer
      --issuer.allow-target-issuers                        If true, issuers are also watched on the target cluster of controller issuer
      --issuer.cascade-delete                              If true, certificate secrets are deleted if dependent resources (certificate, ingress) are deleted of controller issuer
      --issuer.cert-class string                           Identifier used to differentiate responsible controllers for entries of controller issuer
      --issuer.default-issuer string                       name of default issuer (from default cluster) of controller issuer
      --issuer.default-issuer-domain-ranges string         domain range restrictions when using default issuer separated by comma of controller issuer
      --issuer.default-requests-per-day-quota int          Default value for requestsPerDayQuota if not set explicitly in the issuer spec. of controller issuer
      --issuer.default.pool.resync-period duration         Period for resynchronization for pool default of controller issuer
      --issuer.default.pool.size int                       Worker pool size for pool default of controller issuer
      --issuer.dns-class string                            class for creating challenge DNSEntries (in DNS cluster) of controller issuer
      --issuer.dns-namespace string                        namespace for creating challenge DNSEntries (in DNS cluster) of controller issuer
      --issuer.dns-owner-id string                         ownerId for creating challenge DNSEntries of controller issuer
      --issuer.issuer-namespace string                     namespace to lookup issuers on default cluster of controller issuer
      --issuer.issuers.pool.size int                       Worker pool size for pool issuers of controller issuer
      --issuer.pool.resync-period duration                 Period for resynchronization of controller issuer
      --issuer.pool.size int                               Worker pool size of controller issuer
      --issuer.precheck-additional-wait duration           additional wait time after DNS propagation check of controller issuer
      --issuer.precheck-nameservers string                 DNS nameservers used for checking DNS propagation. If explicity set empty, it is tried to read them from /etc/resolv.conf of controller issuer
      --issuer.propagation-timeout duration                propagation timeout for DNS challenge of controller issuer
      --issuer.renewal-overdue-window duration             certificate is counted as 'renewal overdue' if its validity period is shorter (metrics cert_management_overdue_renewal_certificates) of controller issuer
      --issuer.renewal-window duration                     certificate is renewed if its validity period is shorter of controller issuer
      --issuer.revocations.pool.size int                   Worker pool size for pool revocations of controller issuer
      --issuer.secrets.pool.size int                       Worker pool size for pool secrets of controller issuer
      --issuers.pool.size int                              Worker pool size for pool issuers
      --kubeconfig string                                  default cluster access
      --kubeconfig.disable-deploy-crds                     disable deployment of required crds for cluster default
      --kubeconfig.id string                               id for cluster default
      --kubeconfig.migration-ids string                    migration id for cluster default
      --lease-duration duration                            lease duration
      --lease-name string                                  name for lease object
      --lease-renew-deadline duration                      lease renew deadline
      --lease-resource-lock string                         determines which resource lock to use for leader election, defaults to 'leases'
      --lease-retry-period duration                        lease retry period
  -D, --log-level string                                   logrus log level
      --maintainer string                                  maintainer key for crds (default "cert-controller-manager")
      --name string                                        name used for controller manager (default "cert-controller-manager")
      --namespace string                                   namespace for lease (default "kube-system")
  -n, --namespace-local-access-only                        enable access restriction for namespace local access only (deprecated)
      --omit-lease                                         omit lease for development
      --plugin-file string                                 directory containing go plugins
      --pool.resync-period duration                        Period for resynchronization
      --pool.size int                                      Worker pool size
      --precheck-additional-wait duration                  additional wait time after DNS propagation check
      --precheck-nameservers string                        DNS nameservers used for checking DNS propagation. If explicity set empty, it is tried to read them from /etc/resolv.conf
      --propagation-timeout duration                       propagation timeout for DNS challenge
      --renewal-overdue-window duration                    certificate is counted as 'renewal overdue' if its validity period is shorter (metrics cert_management_overdue_renewal_certificates)
      --renewal-window duration                            certificate is renewed if its validity period is shorter
      --revocations.pool.size int                          Worker pool size for pool revocations
      --secrets.pool.size int                              Worker pool size for pool secrets
      --server-port-http int                               HTTP server port (serving /healthz, /metrics, ...)
      --service-cert.cert-class string                     Identifier used to differentiate responsible controllers for entries of controller service-cert
      --service-cert.cert-target-class string              Identifier used to differentiate responsible dns controllers for target entries of controller service-cert
      --service-cert.default.pool.resync-period duration   Period for resynchronization for pool default of controller service-cert
      --service-cert.default.pool.size int                 Worker pool size for pool default of controller service-cert
      --service-cert.pool.resync-period duration           Period for resynchronization of controller service-cert
      --service-cert.pool.size int                         Worker pool size of controller service-cert
      --service-cert.target-name-prefix string             name prefix in target namespace for cross cluster generation of controller service-cert
      --service-cert.target-namespace string               target namespace for cross cluster generation of controller service-cert
      --service-cert.targets.pool.size int                 Worker pool size for pool targets of controller service-cert
      --source string                                      source cluster to watch for ingresses and services
      --source.disable-deploy-crds                         disable deployment of required crds for cluster source
      --source.id string                                   id for cluster source
      --source.migration-ids string                        migration id for cluster source
      --target string                                      target cluster for certificates
      --target-name-prefix string                          name prefix in target namespace for cross cluster generation
      --target-namespace string                            target namespace for cross cluster generation
      --target.disable-deploy-crds                         disable deployment of required crds for cluster target
      --target.id string                                   id for cluster target
      --target.migration-ids string                        migration id for cluster target
      --targets.pool.size int                              Worker pool size for pool targets
  -v, --version                                            version for cert-controller-manager
```

## Renewal of Certificates

Certificates created with an `ACME` issuer are automatically renewed. With the standard configuration,
the certificate is renewed 30 days before it validity expires.
For example, if [Let's Encrypt](https://letsencrypt.org/) is used as certificate authority, a certificate
is always valid for 90 days and will be rolled 30 days before it expires by updating the referenced `Secret`
in the `Certificate` object.  
The configuration can be changed with the command line parameter `--issuer.renewal-window`.

## Revoking Certificates

Certificates created with an `ACME` issuer can also be revoked if private key of the certificate
is not longer safe. This page about [Revoking certificates on Let's Encrypt](https://letsencrypt.org/docs/revoking/)
list various reasons:
> For instance, you might accidentally share the private key on a public website; hackers might copy the private key off 
> of your servers; or hackers might take temporary control over your servers or your DNS configuration, and use that to
> validate and issue a certificate for which they hold the private key.

Revoking a certificate is quite simple. You create a `CertificateRevocation` object on the source cluster with a reference
to the `Certificate` object to be revoked.

```yaml
apiVersion: cert.gardener.cloud/v1alpha1
kind: CertificateRevocation
metadata:
  name: revoke-sample
  namespace: default
spec:
  certificateRef:
    name: mycert
    namespace: default
    
  # Uncomment the following line if certificate should be renewed before revoking the old one(s)
  #renew: true
  
  # Optionally specify a qualifying date. All certificates requested before this date will be revoked.
  # If not specified, the current time is used by default.
  #qualifyingDate: "2020-12-22T17:00:35Z"
```

The `cert-controller-manager` will then perform several steps.

1. Using the certificate secret it looks for other `Certificate` objects using the same certificate. The "same" 
   certificate means same issuer, *Common Name*, and *DNS Names*. All found objects will be reconciled too.
2. It will look for other valid certificate secrets older than the qualifying date. Concretely this will
   deal with unused certificates, which are still valid. As a certificate is renewed 30 days before the end of validity,
   the old certificate is still valid, but not used anymore.
3. All found certificate secrets are revoked and marked with an annotation `cert.gardener.cloud/revoked: "true"`
4. The state of all found `Certificate` objects is set to `Revoked`
5. The state of the `CertificateRevocation` object is set to `Applied`.
   Additionally, the status of the `CertificateRevocation` object contains more details about revoked
   objects and secrets:
   
   ```yaml
   apiVersion: cert.gardener.cloud/v1alpha1
   kind: CertificateRevocation
   metadata:
     name: revoke-sample
     namespace: default
   spec:
     certificateRef:
       name: mycert
       namespace: default
     qualifyingDate: "2020-12-22T17:00:35Z"
   status:
     message: certificate(s) revoked
     objects:
       revoked:
       - name: mycert
         namespace: default
     revocationApplied: "2020-12-22T17:09:32Z"
     secrets:
       revoked:
       - name: cert-backup-default-issuer-8a7e93f7-sks7p
         namespace: kube-system
         serialNumber: fa:3f:9a:5e:ac:47:ee:d1:91:a6:31:a7:43:6f:8a:7e:93:f7
     state: Applied
   ```
   
   The secrets listed in the status are only the internal backups maintained by the `cert-controller-manager`.
   The actual secrets used by the `Certificate` objects are not listed, but nonetheless marked as revoked.

### Revoking certificates with renewal

With this variant the certificate is renewed, before the old one(s) are revoked. This means the 
certificate secrets of the `Certificate` objects will contain newly requested certificates and
the old certificate(s) will be revoked afterwards.

For this purpose, set `renew: true` in the spec of the `CertificateRevocation` object:

```yaml
apiVersion: cert.gardener.cloud/v1alpha1
kind: CertificateRevocation
metadata:
  name: revoke-sample
  namespace: default
spec:
  certificateRef:
    name: mycert
    namespace: default
  renew: true
```

In this case, the status will list the **renewed** `Certificate` objects:

```yaml
apiVersion: cert.gardener.cloud/v1alpha1
kind: CertificateRevocation
metadata:
  name: revoke-sample
  namespace: default
spec:
  certificateRef:
    name: mycert
    namespace: default
  renew: true
  qualifyingDate: "2020-12-22T17:00:35Z"
status:
  message: certificate renewed and old certificate(s) revoked
  objects:
    renewed:
    - name: mycert
      namespace: default
  revocationApplied: "2020-12-22T17:09:32Z"
  secrets:
    revoked:
    - name: cert-backup-default-issuer-8a7e93f7-sks7p
      namespace: kube-system
      serialNumber: fa:3f:9a:5e:ac:47:ee:d1:91:a6:31:a7:43:6f:8a:7e:93:f7
  state: Applied
```

### Checking OCSP revocation using OpenSSL

To verify the OCSP revocation of the X509 certificate of a `Certificate` object,
you can use the tool `hack/check-cert-secret.sh` in this repository.

Usage:

```bash
hack/check-cert-secret.sh check-revoke mynamespace mycertname
```
Here *mynamespace* and *mycertname* are the namespace and the name of the certificate object.

## Metrics

Metrics are exposed for Prometheus if the command line option `--server-port-http <port>` is specified.
The endpoint URL is `http://<pod-ip>:<port>/metrics`.
Besides the default Go metrics, the following cert-management specific metrics are provided:

| Name                                         | Labels               | Description                                    |
| -------------------------------------------- | -------------------- | ---------------------------------------------- |
| cert_management_acme_account_registrations   | uri, email, issuer   | ACME account registrations                     |
| cert_management_acme_orders                  | issuer, success, dns_challenges, renew | Number of ACME orders        |
| cert_management_cert_entries                 | issuer, issuertype   | Total number of certificate objects per issuer |
| cert_management_acme_active_dns_challenges   | issuer               | Currently active number of ACME DNS challenges |
| cert_management_overdue_renewal_certificates | -                    | Number of certificate objects with certificate's renewal overdue |
| cert_management_revoked_certificates         | -                    | Number of certificate objects with revoked certificate |
| cert_management_secrets                      | classification       | Number of certificate secrets per classification (only updated on startup and every 24h on GC of secrets). Currently there are three classifications: `total` = total number of certificate secrets on the source cluster, `revoked` = number of revoked certificate secrets, `backup`= number of backups of certificate secrets (every certificate has a backup secret in the `kube-system` namespace to allow revocation even if it is not used anymore) |

## Development

For development it is recommended to use the issuer-staging

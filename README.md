# cert-management

[![reuse compliant](https://reuse.software/badge/reuse-compliant.svg)](https://reuse.software/)

Manages TLS certificates in Kubernetes clusters using custom resources.
Currently, it supports certificate authorities using the [Automatic Certificate Management Environment (ACME)](https://en.wikipedia.org/wiki/Automated_Certificate_Management_Environment) like [Let's Encrypt](https://letsencrypt.org/).

In a multi-cluster environment like Gardener, using existing open source projects
for certificate management like [cert-manager](https://github.com/jetstack/cert-manager) becomes cumbersome.
With this project the separation of concerns between multiple clusters is realized more easily.
The cert-controller-manager runs in a **secured cluster** where the issuer secrets are stored.
At the same time it watches an untrusted **source cluster** and can provide certificates for it.
The cert-controller-manager relies on DNS challenges for validating the domain names of the certificates.
For this purpose it creates DNSEntry custom resources (in a possible separate **dns cluster**) to be handled by the compagnion dns-controller-manager from [external-dns-management](https://github.com/gardener/external-dns-management).

## Setting up Issuers

Before you can obtain certificates from a certificate authority (CA), you need to set up an issuer.
The issuer is specified in the `default` cluster, while the certificates are specified in the `source` cluster.

The issuer custom resource contains the configuration and registration data for your account at the CA.

Currently, the `cert-controller-manager` only supports certificate authorities via the
[Automatic Certificate Management Environment (ACME)](https://en.wikipedia.org/wiki/Automated_Certificate_Management_Environment) protocol like [Let's Encrypt](https://letsencrypt.org/).

Two modes are supported:

- auto registration
- using an existing account

### Auto registration

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

### Using existing account

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

## Requesting a Certificate

To obtain a certificate for a domain, you specify a certificate custom resource on the `source` cluster.
You can specify the issuer explicitly by reference. If there is no issuer reference, the default issuer is
used (provided as command line option). You must either specify the `commonName` and further optional `dnsNames` or
you can also start with a certificate signing request (CSR).

For domain validation, the `cert-controller-manager` only supports DNS challenges. For this purpose it relies
on the `dns-controller-manager` from the [external-dns-management](https://github.com/gardener/external-dns-management)
project.
If any domain name (`commonName` or any item from `dnsNames`) needs to be validated, it create a custom resource
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

## Requesting a Certificate for Ingress 

Add the annotation `cert.gardener.cloud/purpose: managed` to the Ingress resource.
The `cert-controller-manager` will then automatically request a certificate for all domains given by the hosts in the
`tls` section of the Ingress spec.

For compatibility with the [Gardener Cert-Broker](https://github.com/gardener/cert-broker), you can
alternatively use the label `garden.sapcloud.io/purpose: managed-cert` for the same outcome.

See also [examples/40-ingress-echoheaders.yaml](./examples/40-ingress-echoheaders.yaml):

### Process

1. Create the Ingress Resource (optional)

    In order to request a certificate for a domain managed by `cert-controller-manager` an Ingress is required.
    In case you don’t already have one, take the following as an example:

    ```yaml
    apiVersion: networking.k8s.io/v1beta1
    kind: Ingress
    metadata:
      name: vuejs-ingress
    spec:
      tls:
      # Gardener managed default domain.
      # Must not exceed 64 characters.
      - hosts:
        - test.ingress.<GARDENER-CLUSTER>.<GARDENER-PROJECT>.shoot.example.com
        # Certificate and private key reside in this secret.
        secretName: testsecret-tls
      rules:
      - host: test.ingress.<GARDENER-CLUSTER>.<GARDENER-PROJECT>.shoot.example.com
        http:
          paths:
          - backend:
              serviceName: vuejs-svc
              servicePort: 8080
    ```

2. Annotate the Ingress Resource

   The annotation `cert.gardener.cloud/purpose: managed` instructs `cert-controller-manager` to handle certificate issuance for the domains found in labeled Ingress.

    ```yaml
    apiVersion: networking.k8s.io/v1beta1
    kind: Ingress
    metadata:
      name: tls-example-ingress
      annotations:
        # Let Gardener manage certificates for this Ingress.
        cert.gardener.cloud/purpose: managed
    ...
    ```

3. Check status

   A `certificate` custom resource is created in the same namespace of the `source` cluster.
   You can either check the status of this certificate resource with `kubectl get cert` or you can check
   the events for the ingress with `kubectl get events`

   The certificate is stored in the secret as specified in the Ingress resource.

## Requesting a Certificate for Service 

If you have a service of type `LoadBalancer`, you can use the annotation `cert.gardener.cloud/secretname` together
with the annotation `dns.gardener.cloud/dnsnames` from the `dns-controller-manager` to trigger automatic creation of a certificate.

```yaml
apiVersion: v1
kind: Service
metadata:
  annotations:
    cert.gardener.cloud/secretname: test-service-secret
    dns.gardener.cloud/dnsnames: test-service.demo.mydomain.com
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
  used for storing generated certificates
  The path to the kubeconfig is specified with command line option `--target`.  
  If option is omitted, the source cluster is also used for target.  
  
### Usage
The complete list of options is:

```text
Usage:
  cert-controller-manager [flags]

Flags:
      --bind-address-http string                           HTTP server bind address
      --cascade-delete                                     If true, certificate secrets are deleted if dependent resources (certificate, ingress) are deleted
      --cert-class string                                  Identifier used to differentiate responsible controllers for entries
      --cert-target-class string                           Identifier used to differentiate responsible dns controllers for target entries
      --config string                                      config file
  -c, --controllers string                                 comma separated list of controllers to start (<name>,<group>,all) (default "all")
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
      --grace-period duration                              inactivity grace period for detecting end of cleanup for shutdown
  -h, --help                                               help for cert-controller-manager
      --ingress-cert.cert-class string                     Identifier used to differentiate responsible controllers for entries of controller ingress-cert (default "gardencert")
      --ingress-cert.cert-target-class string              Identifier used to differentiate responsible dns controllers for target entries of controller ingress-cert
      --ingress-cert.default.pool.resync-period duration   Period for resynchronization for pool default of controller ingress-cert (default 2m0s)
      --ingress-cert.default.pool.size int                 Worker pool size for pool default of controller ingress-cert (default 2)
      --ingress-cert.pool.resync-period duration           Period for resynchronization of controller ingress-cert
      --ingress-cert.pool.size int                         Worker pool size of controller ingress-cert
      --ingress-cert.target-name-prefix string             name prefix in target namespace for cross cluster generation of controller ingress-cert
      --ingress-cert.target-namespace string               target namespace for cross cluster generation of controller ingress-cert
      --ingress-cert.targets.pool.size int                 Worker pool size for pool targets of controller ingress-cert (default 2)
      --issuer-namespace string                            namespace to lookup issuers on default cluster
      --issuer.cascade-delete                              If true, certificate secrets are deleted if dependent resources (certificate, ingress) are deleted of controller issuer
      --issuer.cert-class string                           Identifier used to differentiate responsible controllers for entries of controller issuer
      --issuer.default-issuer string                       name of default issuer (from default cluster) of controller issuer (default "default-issuer")
      --issuer.default-issuer-domain-ranges string         domain range restrictions when using default issuer separated by comma of controller issuer
      --issuer.default-requests-per-day-quota int          Default value for requestsPerDayQuota if not set explicitly in the issuer spec. of controller issuer (default 10000)
      --issuer.default.pool.resync-period duration         Period for resynchronization for pool default of controller issuer (default 24h0m0s)
      --issuer.default.pool.size int                       Worker pool size for pool default of controller issuer (default 2)
      --issuer.dns-class string                            class for creating challenge DNSEntries (in DNS cluster) of controller issuer
      --issuer.dns-namespace string                        namespace for creating challenge DNSEntries (in DNS cluster) of controller issuer
      --issuer.dns-owner-id string                         ownerId for creating challenge DNSEntries of controller issuer
      --issuer.issuer-namespace string                     namespace to lookup issuers on default cluster of controller issuer (default "default")
      --issuer.issuers.pool.size int                       Worker pool size for pool issuers of controller issuer (default 1)
      --issuer.pool.resync-period duration                 Period for resynchronization of controller issuer
      --issuer.pool.size int                               Worker pool size of controller issuer
      --issuer.precheck-additional-wait duration           additional wait time after DNS propagation check of controller issuer (default 10s)
      --issuer.precheck-nameservers string                 DNS nameservers used for checking DNS propagation. If explicity set empty, it is tried to read them from /etc/resolv.conf of controller issuer (default "8.8.8.8:53,8.8.4.4:53")
      --issuer.propagation-timeout duration                propagation timeout for DNS challenge of controller issuer (default 1m0s)
      --issuer.renewal-window duration                     certificate is renewed if its validity period is shorter of controller issuer (default 720h0m0s)
      --issuer.secrets.pool.size int                       Worker pool size for pool secrets of controller issuer (default 1)
      --issuers.pool.size int                              Worker pool size for pool issuers
      --kubeconfig string                                  default cluster access
      --kubeconfig.disable-deploy-crds                     disable deployment of required crds for cluster default
      --kubeconfig.id string                               id for cluster default
      --lease-duration duration                            lease duration (default 15s)
      --lease-name string                                  name for lease object
      --lease-renew-deadline duration                      lease renew deadline (default 10s)
      --lease-retry-period duration                        lease retry period (default 2s)
  -D, --log-level string                                   logrus log level
      --maintainer string                                  maintainer key for crds (defaulted by manager name)
      --name string                                        name used for controller manager
      --namespace string                                   namespace for lease (default "kube-system")
  -n, --namespace-local-access-only                        enable access restriction for namespace local access only (deprecated)
      --omit-lease                                         omit lease for development
      --plugin-file string                                 directory containing go plugins
      --pool.resync-period duration                        Period for resynchronization
      --pool.size int                                      Worker pool size
      --precheck-additional-wait duration                  additional wait time after DNS propagation check
      --precheck-nameservers string                        DNS nameservers used for checking DNS propagation. If explicity set empty, it is tried to read them from /etc/resolv.conf
      --propagation-timeout duration                       propagation timeout for DNS challenge
      --renewal-window duration                            certificate is renewed if its validity period is shorter
      --secrets.pool.size int                              Worker pool size for pool secrets
      --server-port-http int                               HTTP server port (serving /healthz, /metrics, ...)
      --service-cert.cert-class string                     Identifier used to differentiate responsible controllers for entries of controller service-cert (default "gardencert")
      --service-cert.cert-target-class string              Identifier used to differentiate responsible dns controllers for target entries of controller service-cert
      --service-cert.default.pool.resync-period duration   Period for resynchronization for pool default of controller service-cert (default 2m0s)
      --service-cert.default.pool.size int                 Worker pool size for pool default of controller service-cert (default 2)
      --service-cert.pool.resync-period duration           Period for resynchronization of controller service-cert
      --service-cert.pool.size int                         Worker pool size of controller service-cert
      --service-cert.target-name-prefix string             name prefix in target namespace for cross cluster generation of controller service-cert
      --service-cert.target-namespace string               target namespace for cross cluster generation of controller service-cert
      --service-cert.targets.pool.size int                 Worker pool size for pool targets of controller service-cert (default 2)
      --source string                                      source cluster to watch for ingresses and services
      --source.disable-deploy-crds                         disable deployment of required crds for cluster source
      --source.id string                                   id for cluster source
      --target string                                      target cluster for certificates
      --target-name-prefix string                          name prefix in target namespace for cross cluster generation
      --target-namespace string                            target namespace for cross cluster generation
      --target.disable-deploy-crds                         disable deployment of required crds for cluster target
      --target.id string                                   id for cluster target
      --targets.pool.size int                              Worker pool size for pool targets
  -v, --version                                            version for cert-controller-manager
```
 
## Development

For development it is recommended to use the issuer-staging

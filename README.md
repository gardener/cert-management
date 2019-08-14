# cert-management

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
by creating a private key and performing the registration at the CA.

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

The `cert-controller-manager` supports the same mechanism as the [Gardener Cert-Broker](https://github.com/gardener/cert-broker)
for automatically requesting a certificate for an ingress resource.
You need to add the label `garden.sapcloud.io/purpose: managed-cert` to the Ingress resource.

See also [examples/40-ingress-echoheaders.yaml](./examples/40-ingress-echoheaders.yaml):

### Process

1. Create Ingress Resource (optional)

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

2. Label Ingress Resource

   The label `garden.sapcloud.io/purpose: managed-cert` instructs `cert-controller-manager` to handle certificate issuance for the domains found in labeled Ingress.

    ```yaml
    apiVersion: networking.k8s.io/v1beta1
    kind: Ingress
    metadata:
      name: tls-example-ingress
      labels:
        # Let Gardener manage certificates for this Ingress.
        garden.sapcloud.io/purpose: managed-cert
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

## Development

For development it is recommended to use the issuer-staging

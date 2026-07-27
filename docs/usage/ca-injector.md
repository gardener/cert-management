# CA Injector

The CA injector is a feature of the `cert-controller-manager-next-generation` that automatically
populates the `caBundle` field of Kubernetes resources with a CA certificate managed by
cert-management. This removes the need to manually update `caBundle` fields whenever a CA
certificate rotates.

A typical use case is keeping admission webhook configurations in sync with the CA certificate
of the serving certificate so that the API server can always verify webhook TLS connections.

## Prerequisites

- `cert-controller-manager-next-generation` deployed and running
- A `Certificate` resource (or a `Secret`) managed by cert-management whose `ca.crt` you want
  to inject

## Enabling the CA Injector

The CA injector is **disabled by default**. Enable it in the `CertManagerConfiguration` file
passed to `cert-controller-manager-next-generation` via the `--config` flag:

```yaml
apiVersion: cert.gardener.cloud/v1alpha1
kind: CertManagerConfiguration
controllers:
  caInjector:
    enabled: true        # default: false
    concurrentSyncs: 1   # optional, default: 1
```

## Injectable Resource Types

The CA injector can patch the following cluster-scoped resource kinds. Add an inject annotation
(see below) to any of them to opt in.

| Resource kind                    | Field patched                                         |
|----------------------------------|-------------------------------------------------------|
| `ValidatingWebhookConfiguration` | `webhooks[*].clientConfig.caBundle`                   |
| `MutatingWebhookConfiguration`   | `webhooks[*].clientConfig.caBundle`                   |
| `CustomResourceDefinition`       | `spec.conversion.webhook.clientConfig.caBundle`       |
| `APIService`                     | `spec.caBundle`                                       |

All webhook entries on a `ValidatingWebhookConfiguration` or `MutatingWebhookConfiguration` are
patched simultaneously — there is no per-entry selection.

## Injecting from a Certificate

Use the `cert.gardener.cloud/inject-ca-from` annotation on the injectable resource. The value is
`<namespace>/<certificate-name>` referencing a cert-management `Certificate` resource.
The `ca.crt` key from the Secret named in that `Certificate`'s `spec.secretName` (or
`spec.secretRef`) is injected.

### ValidatingWebhookConfiguration

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: my-validator
  annotations:
    cert.gardener.cloud/inject-ca-from: "cert-management/my-webhook-cert"
webhooks:
  - name: validate.example.com
    clientConfig:
      service:
        namespace: my-namespace
        name: my-webhook-service
        path: /validate
      # caBundle is managed by the ca-injector — do not set manually
```

### MutatingWebhookConfiguration

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: my-mutator
  annotations:
    cert.gardener.cloud/inject-ca-from: "cert-management/my-webhook-cert"
webhooks:
  - name: mutate.example.com
    clientConfig:
      service:
        namespace: my-namespace
        name: my-webhook-service
        path: /mutate
      # caBundle is managed by the ca-injector — do not set manually
```

### CustomResourceDefinition

```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: foos.example.com
  annotations:
    cert.gardener.cloud/inject-ca-from: "cert-management/my-conversion-cert"
spec:
  conversion:
    strategy: Webhook
    webhook:
      conversionReviewVersions: ["v1"]
      clientConfig:
        service:
          namespace: my-namespace
          name: my-conversion-service
          path: /convert
        # caBundle is managed by the ca-injector — do not set manually
```

### APIService

```yaml
apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata:
  name: v1alpha1.example.com
  annotations:
    cert.gardener.cloud/inject-ca-from: "cert-management/my-apiservice-cert"
spec:
  group: example.com
  version: v1alpha1
  service:
    namespace: my-namespace
    name: my-apiservice
  groupPriorityMinimum: 100
  versionPriority: 100
  # caBundle is managed by the ca-injector — do not set manually
```

## Injecting directly from a Secret

Use the `cert.gardener.cloud/inject-ca-from-secret` annotation when you want to inject directly
from a `Secret` rather than via a `Certificate`. The value is `<namespace>/<secret-name>`.

> [!WARNING]
> The target `Secret` must carry the annotation
> `cert.gardener.cloud/allow-direct-injection: "true"`. Without this annotation on the Secret,
> injection is **refused** — the target resource is left unchanged.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-ca-secret
  namespace: cert-management
  annotations:
    cert.gardener.cloud/allow-direct-injection: "true"
type: kubernetes.io/tls
data:
  ca.crt: <base64-encoded CA certificate>
  tls.crt: ...
  tls.key: ...
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: my-validator
  annotations:
    cert.gardener.cloud/inject-ca-from-secret: "cert-management/my-ca-secret"
webhooks:
  - name: validate.example.com
    clientConfig:
      service:
        namespace: my-namespace
        name: my-webhook-service
        path: /validate
      # caBundle is managed by the ca-injector — do not set manually
```

## Behavior

- **All entries patched**: every webhook entry in a `ValidatingWebhookConfiguration` or
  `MutatingWebhookConfiguration` receives the same CA bundle.
- **Overwrites existing values**: any manually set `caBundle` is replaced when the annotated
  resource is next reconciled.
- **Missing CA is non-destructive**: if `ca.crt` is absent or empty in the source Secret, the
  target is left unchanged and the reconcile is retried automatically.
- **Event-driven updates**: the ca-injector watches `Certificate` and `Secret` resources. When a
  CA rotates, all dependent injectables are reconciled promptly without manual intervention.

## RBAC

The `cert-controller-manager-next-generation` service account requires the following permissions
for the ca-injector controllers:

| Resource                                     | API group                            | Verbs                              |
|----------------------------------------------|--------------------------------------|------------------------------------|
| `validatingwebhookconfigurations`            | `admissionregistration.k8s.io`       | `get`, `list`, `watch`, `update`   |
| `mutatingwebhookconfigurations`              | `admissionregistration.k8s.io`       | `get`, `list`, `watch`, `update`   |
| `customresourcedefinitions`                  | `apiextensions.k8s.io`               | `get`, `list`, `watch`, `update`   |
| `apiservices`                                | `apiregistration.k8s.io`             | `get`, `list`, `watch`, `update`   |
| `secrets`                                    | `""`  (core)                         | `get`, `list`, `watch`             |
| `certificates`                               | `cert.gardener.cloud`                | `get`, `list`, `watch`             |
| `events`                                     | `""`  (core)                         | `create`, `patch`                  |

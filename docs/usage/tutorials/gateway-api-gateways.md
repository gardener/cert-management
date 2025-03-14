# Using annotated Gateway API Gateway and/or HTTPRoutes as Source
This tutorial describes how to use annotated Gateway API resources as source for `Certificate` in the cert-controller-manager.

The cert-controller-manager supports the resources `Gateway` and `HTTPRoute`. 

*Note: The cert-management is used together with the [external-dns-management](https://github.com/gardener/external-dns-management), typically.
See [its own tutorial](https://github.com/gardener/external-dns-management/blob/master/docs/usage/tutorials/gateway-api-gateways.md)
for how to automatically create DNS records by annotations.*

## Install cert-controller-manager
First, install the cert-controller-manager using the Helm charts.

## Install Istio on your cluster

Follow the Istio [Kubernetes Gateway API](https://istio.io/latest/docs/tasks/traffic-management/ingress/gateway-api/) to 
install the Gateway API and to install Istio.

These are the typical commands for the Istio installation with the Kubernetes Gateway API:

```bash
export KUEBCONFIG=...
curl -L https://istio.io/downloadIstio | sh -
kubectl get crd gateways.gateway.networking.k8s.io &> /dev/null || \
  { kubectl kustomize "github.com/kubernetes-sigs/gateway-api/config/crd?ref=v1.0.0" | kubectl apply -f -; }
istioctl install --set profile=minimal -y
kubectl label namespace default istio-injection=enabled
```

## Verify that Gateway Source works

### Install a sample service
With automatic sidecar injection:
```bash
$ kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.20/samples/httpbin/httpbin.yaml
```

Note: The sample service is not used in the following steps. It is deployed for illustration purposes only. 
To use it with certificates, you have to add an HTTPS port for it.

### Using a Gateway as a source

Deploy the Gateway API configuration including a single exposed route (i.e., /get):
```bash
kubectl create namespace istio-ingress
kubectl apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1beta1
kind: Gateway
metadata:
  name: gateway
  namespace: istio-ingress
  annotations:
    #cert.gardener.cloud/dnsnames: "*.example.com" # alternative if you want to control the dns names explicitly.
    cert.gardener.cloud/purpose: managed
spec:
  gatewayClassName: istio
  listeners:
  - name: default
    hostname: "*.example.com"  # this is used by cert-controller-manager to extract DNS names
    port: 443
    protocol: HTTPS
    allowedRoutes:
      namespaces:
        from: All
    tls:                       # important: tls section must be defined with exactly one certificateRefs item
      certificateRefs:
        - name: foo-example-com
---
apiVersion: gateway.networking.k8s.io/v1beta1
kind: HTTPRoute
metadata:
  name: http
  namespace: default
spec:
  parentRefs:
  - name: gateway
    namespace: istio-ingress
  hostnames: ["httpbin.example.com"]  # this is used by cert-controller-manager to extract DNS names too
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /get
    backendRefs:
    - name: httpbin
      port: 8000
EOF
```

You should now see a created `Certificate` resource similar to:

```bash
$ kubectl -n istio-ingress get cert -oyaml
apiVersion: v1
items:
- apiVersion: cert.gardener.cloud/v1alpha1
  kind: Certificate
  metadata:
    generateName: gateway-gateway-
    name: gateway-gateway-kdw6h
    namespace: istio-ingress
    ownerReferences:
    - apiVersion: gateway.networking.k8s.io/v1
      blockOwnerDeletion: true
      controller: true
      kind: Gateway
      name: gateway
  spec:
    commonName: '*.example.com'
    secretRef:
      name: foo-example-com
  status:
    ...
kind: List
metadata:
  resourceVersion: ""
```

#### Using a HTTPRoute as a source

If the `Gateway` resource is annotated with `cert.gardener.cloud/purpose: managed`,
hostnames from all referencing  `HTTPRoute` resources are automatically extracted.
These resources don't need an additional annotation.

Deploy the Gateway API configuration including a single exposed route (i.e., /get):

```bash
kubectl create namespace istio-ingress
kubectl apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1beta1
kind: Gateway
metadata:
  name: gateway
  namespace: istio-ingress
  annotations:
    cert.gardener.cloud/purpose: managed
spec:
  gatewayClassName: istio
  listeners:
  - name: default
    hostname: null  # not set 
    port: 443
    protocol: HTTPS
    allowedRoutes:
      namespaces:
        from: All
    tls:                            # important: tls section must be defined with exactly one certificateRefs item
      certificateRefs:
        - name: foo-example-com
---
apiVersion: gateway.networking.k8s.io/v1beta1
kind: HTTPRoute
metadata:
  name: http
  namespace: default
spec:
  parentRefs:
  - name: gateway
    namespace: istio-ingress
  hostnames: ["httpbin.example.com"]  # this is used by dns-controller-manager to extract DNS names too
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /get
    backendRefs:
    - name: httpbin
      port: 8000
EOF
```

This should show a similar `Certificate` resource as above.

# Using annotated Istio Gateway and/or Istio Virtual Service as Source
This tutorial describes how to use annotated Istio Gateway resources as source for `Certificate` resources in the cert-controller-manager.

*Note: The cert-management is used together with the [external-dns-management](https://github.com/gardener/external-dns-management), typically. 
See [its own tutorial](https://github.com/gardener/external-dns-management/blob/master/docs/usage/tutorials/istio-gateways.md) 
for how to automatically create DNS records by annotations.*

## Install dns-controller-manager
First, install the cert-controller-manager using the Helm charts.

## Install Istio on your cluster

Follow the [Istio Getting Started](https://istio.io/latest/docs/setup/getting-started/) to download and install Istio.

These are the typical commands for the istio demo installation

```bash
export KUEBCONFIG=...
curl -L https://istio.io/downloadIstio | sh -
istioctl install --set profile=demo -y
kubectl label namespace default istio-injection=enabled
```

*Note: If you are using a KinD cluster, the istio-ingressgateway service may be pending forever.*

```bash
$ kubectl -n istio-system get svc istio-ingressgateway
NAME                   TYPE           CLUSTER-IP     EXTERNAL-IP   PORT(S)                                                                      AGE
istio-ingressgateway   LoadBalancer   10.96.88.189   <pending>     15021:30590/TCP,80:30185/TCP,443:30075/TCP,31400:30129/TCP,15443:30956/TCP   13m
```

In this case, you may patch the status for demo purposes (of course it still would not accept connections)
```bash
kubectl -n istio-system patch svc istio-ingressgateway --type=merge --subresource status --patch '{"status":{"loadBalancer":{"ingress":[{"ip":"1.2.3.4"}]}}}'
```

## Verify that Istio Gateway/VirtualService Source works

### Install a sample service
With automatic sidecar injection:
```bash
$ kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.20/samples/httpbin/httpbin.yaml
```

### Using a Gateway as a source
#### Create an Istio Gateway:
```bash
$ cat <<EOF | kubectl apply -f -
apiVersion: networking.istio.io/v1
kind: Gateway
metadata:
  name: httpbin-gateway
  namespace: istio-system
  annotations:
    cert.gardener.cloud/purpose: managed
    #cert.gardener.cloud/dnsnames: "*.example.com"                # alternative if you want to control the dns names explicitly.
    #cert.gardener.cloud/secret-namespace: "istio-system"         # optional to specify the namespace where the certificate secret should be created
spec:
  selector:
    istio: ingressgateway # use Istio default gateway implementation
  servers:
  - port:
      number: 443
      name: http
      protocol: HTTPS
    hosts:
    - "httpbin.example.com" # this is used by the dns-controller-manager to extract DNS names
    tls:
      credentialName: my-tls-secret
EOF
```

You should now see a created `Certificate` resource similar to:

```bash
$ kubectl -n istio-system get cert -oyaml
apiVersion: v1
items:
- apiVersion: cert.gardener.cloud/v1alpha1
  kind: Certificate
  metadata:
    generateName: httpbin-gateway-gateway-
    name: httpbin-gateway-gateway-hdbjb
    namespace: istio-system
    ownerReferences:
    - apiVersion: networking.istio.io/v1
      blockOwnerDeletion: true
      controller: true
      kind: Gateway
      name: httpbin-gateway
  spec:
    commonName: httpbin.example.com
    secretRef:
      name: my-tls-secret
  status:
    ...
kind: List
metadata:
  resourceVersion: ""
```

### Using a VirtualService as a source

If the `Gateway` resource is annotated with `cert.gardener.cloud/purpose: managed`,
hosts from all referencing  `VirtualServices` resources are automatically extracted.
These resources don't need an additional annotation.

#### Create an Istio Gateway:
```bash
$ cat <<EOF | kubectl apply -f -
apiVersion: networking.istio.io/v1
kind: Gateway
metadata:
  name: httpbin-gateway
  namespace: istio-system
  annotations:
    cert.gardener.cloud/purpose: managed
spec:
  selector:
    istio: ingressgateway # use Istio default gateway implementation
  servers:
  - port:
      number: 443
      name: https
      protocol: HTTPS
    hosts:
    - "*"
    tls:
      credentialName: my-tls-secret    
EOF
```

#### Configure routes for traffic entering via the Gateway:
```bash
$ cat <<EOF | kubectl apply -f -
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata:
  name: httpbin
  namespace: default  
spec:
  hosts:
  - "httpbin.example.com" # this is used by dns-controller-manager to extract DNS names
  gateways:
  - istio-system/httpbin-gateway
  http:
  - match:
    - uri:
        prefix: /status
    - uri:
        prefix: /delay
    route:
    - destination:
        port:
          number: 8000
        host: httpbin
EOF
```

This should show a similar `Certificate` resource as above.

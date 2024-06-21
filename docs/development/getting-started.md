# Developing cert-management locally with a kind cluster

There is a local setup without dependencies to external services.

## Setting Up the KinD Cluster

```bash
make kind-up
```

You find the kubeconfig at `$PWD/cert-management/dev/kind-kubeconfig.yaml`

This starts a kind cluster with 
- an ACME server (here the Let's Encrypt [Pebble](https://github.com/letsencrypt/pebble), a minimal ACME test server)
- an authoritative DNS server (here [Knot DNS](https://github.com/CZ-NIC/knot))
- the dns-controller-manager from [gardener/external-dns-management](https://github.com/gardener/external-dns-management)

The pebble server is mapped to localhost:5443 on your local machine.
You can use it with the server endpoint `https://localhost:5443/dir`.

## Running cert-controller-manager from command line

Running the cert-controller-manager locally from the command line using the kind cluster
is nearly straight-forward.

There are two configuration issues to overcome.
- The local setup uses a DNS server running on the kind cluster. For checking the DNS propagation, your local 
  cert-controller-manager must use this server (by setting the `precheckNameservers`).
  The make target `local-issuer-up` creates a suitable issuer in the default namespace.  
- Second, as the ACME server uses a self-signed certificate, the local cert-controller-manager must accept it.
  For this purpose, some environment variables need to be set

The complete list of steps are

```bash
make local-issuer-up
source ./dev/source-lego-env.sh
export KUBECONFIG=$PWD/dev/kind-kubeconfig.yaml
make build-local
./cert-controller-manager --default-issuer local-issuer --omit-lease
```

*Note: The local issuer cannot be used from within the kind cluster. If you want to deploy the cert-controller-manager
on the kind cluster, remove the issuer with*

```bash
make local-issuer-down
```

### Test if your setup is working

Now you can check if the issuer has been reconciled successfully:
```bash
$ kubectl get issuer local-issuer
NAME           SERVER                       EMAIL                    STATUS   TYPE   AGE
local-issuer   https://localhost:5443/dir   some.user@certman.kind   Ready    acme   80s
```

You can add a sample certificate for any subdomains of `certman.kind` with
```bash
cat << EOF | kubectl apply -f -
apiVersion: cert.gardener.cloud/v1alpha1
kind: Certificate
metadata:
  name: example
  namespace: default
spec:
  commonName: example.certman.kind
  secretRef:
    name: example
EOF
```

Check the certificate status, after a few seconds you should see
```
$ kubectl get cert example
NAME      COMMON NAME            ISSUER         STATUS   AGE
example   example.certman.kind   local-issuer   Ready    40s
```

## Deletion of KinD Cluster

```bash
make kind-down
```

This deletes the Kind cluster.
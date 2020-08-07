#!/bin/python

# helper script to regenerate helm chart file: partial of charts/cert-management/templates/deployment.yaml


import re

options = """
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
"""

def toCamelCase(name):
  str = ''.join(x.capitalize() for x in re.split("[.-]", name))
  str = str[0].lower() + str[1:]
  return str

excluded = {"name", "help"}
for line in options.split("\n"):
    m = re.match(r"\s+(?:-[^-]+)?--(\S+)\s", line)
    if m:
      name = m.group(1)
      if name != "" and not name in excluded:
        camelCase = toCamelCase(name)
        txt = """        {{- if .Values.configuration.%s }}
        - --%s={{ .Values.configuration.%s }}
        {{- end }}""" % (camelCase, name, camelCase)
        print(txt)

print("\n\n\n")

defaultValues = {
  "serverPortHttp": "8080"
}

print("configuration:")
for line in options.split("\n"):
    m = re.match(r"\s+(?:-[^-]+)?--(\S+)\s", line)
    if m:
      name = m.group(1)
      if name != "" and not name in excluded:
        camelCase = toCamelCase(name)
        if camelCase in defaultValues:
          txt = "  %s: %s" % (camelCase, defaultValues[camelCase])
        else:
          txt = "# %s:" % camelCase
        print(txt)
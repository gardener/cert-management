#!/bin/python

# helper script to regenerate helm chart file: partial of charts/cert-management/templates/deployment.yaml


import re

options = """
      --cascade-delete                                     default for all controller "cascade-delete" options
      --cert-class string                                  default for all controller "cert-class" options
      --cert-target-class string                           default for all controller "cert-target-class" options
  -c, --controllers string                                 comma separated list of controllers to start (<name>,source,target,all) (default "all")
      --cpuprofile string                                  set file for cpu profiling
      --default-issuer string                              default for all controller "default-issuer" options
      --default-issuer-domain-ranges string                default for all controller "default-issuer-domain-ranges" options
      --default-requests-per-day-quota int                 default for all controller "default-requests-per-day-quota" options
      --disable-namespace-restriction                      disable access restriction for namespace local access only
      --dns string                                         cluster for writing challenge DNS entries
      --dns-class string                                   default for all controller "dns-class" options
      --dns-namespace string                               default for all controller "dns-namespace" options
      --dns-owner-id string                                default for all controller "dns-owner-id" options
      --dns.disable-deploy-crds                            disable deployment of required crds for cluster dns
      --dns.id string                                      id for cluster dns
      --grace-period duration                              inactivity grace period for detecting end of cleanup for shutdown
  -h, --help                                               help for cert-controller-manager
      --ingress-cert.cert-class string                     Identifier used to differentiate responsible controllers for entries
      --ingress-cert.cert-target-class string              Identifier used to differentiate responsible dns controllers for target entries
      --ingress-cert.default.pool.resync-period duration   Period for resynchronization of pool default of controller ingress-cert (default: 2m0s)
      --ingress-cert.default.pool.size int                 Worker pool size for pool default of controller ingress-cert (default: 2)
      --ingress-cert.target-name-prefix string             name prefix in target namespace for cross cluster generation
      --ingress-cert.target-namespace string               target namespace for cross cluster generation
      --ingress-cert.targets.pool.size int                 Worker pool size for pool targets of controller ingress-cert (default: 2)
      --issuer-namespace string                            default for all controller "issuer-namespace" options
      --issuer.cascade-delete                              If true, certificate secrets are deleted if dependent resources (certificate, ingress) are deleted
      --issuer.cert-class string                           Identifier used to differentiate responsible controllers for entries
      --issuer.default-issuer string                       name of default issuer (from default cluster)
      --issuer.default-issuer-domain-ranges string         domain range restrictions when using default issuer separated by comma
      --issuer.default-requests-per-day-quota int          Default value for requestsPerDayQuota if not set explicitly in the issuer spec.
      --issuer.default.pool.resync-period duration         Period for resynchronization of pool default of controller issuer (default: 24h0m0s)
      --issuer.default.pool.size int                       Worker pool size for pool default of controller issuer (default: 2)
      --issuer.dns-class string                            class for creating challenge DNSEntries (in DNS cluster)
      --issuer.dns-namespace string                        namespace for creating challenge DNSEntries (in DNS cluster)
      --issuer.dns-owner-id string                         ownerId for creating challenge DNSEntries
      --issuer.issuer-namespace string                     namespace to lookup issuers on default cluster
      --issuer.issuers.pool.size int                       Worker pool size for pool issuers of controller issuer (default: 1)
      --issuer.precheck-additional-wait duration           additional wait time after DNS propagation check
      --issuer.precheck-nameservers string                 DNS nameservers used for checking DNS propagation. If explicity set empty, it is tried to read them from /etc/resolv.conf
      --issuer.propagation-timeout duration                propagation timeout for DNS challenge
      --issuer.renewal-window duration                     certificate is renewed if its validity period is shorter
      --issuer.secrets.pool.size int                       Worker pool size for pool secrets of controller issuer (default: 1)
      --kubeconfig string                                  default cluster access
      --kubeconfig.disable-deploy-crds                     disable deployment of required crds for cluster default
      --kubeconfig.id string                               id for cluster default
  -D, --log-level string                                   logrus log level
      --name string                                        name used for controller manager
      --namespace string                                   namespace for lease
  -n, --namespace-local-access-only                        enable access restriction for namespace local access only (deprecated)
      --omit-lease                                         omit lease for development
      --plugin-dir string                                  directory containing go plugins
      --pool.resync-period duration                        default for all controller "pool.resync-period" options
      --pool.size int                                      default for all controller "pool.size" options
      --precheck-additional-wait duration                  default for all controller "precheck-additional-wait" options
      --precheck-nameservers string                        default for all controller "precheck-nameservers" options
      --propagation-timeout duration                       default for all controller "propagation-timeout" options
      --renewal-window duration                            default for all controller "renewal-window" options
      --server-port-http int                               HTTP server port (serving /healthz, /metrics, ...)
      --service-cert.cert-class string                     Identifier used to differentiate responsible controllers for entries
      --service-cert.cert-target-class string              Identifier used to differentiate responsible dns controllers for target entries
      --service-cert.default.pool.resync-period duration   Period for resynchronization of pool default of controller service-cert (default: 2m0s)
      --service-cert.default.pool.size int                 Worker pool size for pool default of controller service-cert (default: 2)
      --service-cert.target-name-prefix string             name prefix in target namespace for cross cluster generation
      --service-cert.target-namespace string               target namespace for cross cluster generation
      --service-cert.targets.pool.size int                 Worker pool size for pool targets of controller service-cert (default: 2)
      --source string                                      source cluster to watch for ingresses and services
      --source.disable-deploy-crds                         disable deployment of required crds for cluster source
      --source.id string                                   id for cluster source
      --target string                                      target cluster for certificates
      --target-name-prefix string                          default for all controller "target-name-prefix" options
      --target-namespace string                            default for all controller "target-namespace" options
      --target.disable-deploy-crds                         disable deployment of required crds for cluster target
      --target.id string                                   id for cluster target
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
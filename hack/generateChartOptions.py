#!/bin/python

# helper script to regenerate helm chart file: partial of charts/cert-management/templates/deployment.yaml


import re

options = """
cert-class
cert-target-class
certificate.cert-class
certificate.default-issuer
certificate.default-issuer-domain-range
certificate.default.pool.resync-period
certificate.default.pool.size
certificate.dns-namespace
certificate.dns-owner-id
certificate.issuer-namespace
certificate.renewal-window
controllers
cpuprofile
default-issuer
default-issuer-domain-range
disable-namespace-restriction
dns
dns-namespace
dns-owner-id
dns.id
help
ingress-cert.cert-class
ingress-cert.cert-target-class
ingress-cert.default.pool.resync-period
ingress-cert.default.pool.size
ingress-cert.target-name-prefix
ingress-cert.target-namespace
ingress-cert.targets.pool.size
issuer-namespace
issuer.default.pool.size
issuer.secrets.pool.size
kubeconfig
kubeconfig.id
log-level
name
namespace
namespace-local-access-only
omit-lease
plugin-dir
pool.resync-period
pool.size
renewal-window
server-port-http
service-cert.cert-class
service-cert.cert-target-class
service-cert.default.pool.resync-period
service-cert.default.pool.size
service-cert.target-name-prefix
service-cert.target-namespace
service-cert.targets.pool.size
source
source.id
target
target-name-prefix
target-namespace
target.id
"""

def toCamelCase(name):
  str = ''.join(x.capitalize() for x in re.split("[.-]", name))
  str = str[0].lower() + str[1:]
  return str

excluded = {"name", "help"}
for name in options.split("\n"):
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
for name in options.split("\n"):
    if name != "" and not name in excluded:
        camelCase = toCamelCase(name)
        if camelCase in defaultValues:
            txt = "  %s: %s" % (camelCase, defaultValues[camelCase])
        else:
            txt = "# %s:" % camelCase
        print(txt)

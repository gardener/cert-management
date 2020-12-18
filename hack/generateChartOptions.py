#!/bin/python

# SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

# helper script to regenerate helm chart file: partial of charts/cert-management/templates/deployment.yaml


import re
import os

helpFilename = "/tmp/cert-controller-manager-help.txt"
rc = os.system("make build-local && ./cert-controller-manager --help | grep ' --' > {}".format(helpFilename))
if rc != 0:
  exit(rc)
f = open(helpFilename,"r")
options = f.read()
os.remove(helpFilename)

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
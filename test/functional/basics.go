/*
 * Copyright 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 *
 */

package functional

import (
	"os"
	"text/template"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"

	"github.com/gardener/cert-management/test/functional/config"
)

var basicTemplate = `
apiVersion: cert.gardener.cloud/v1alpha1
kind: Issuer
metadata:
  name: {{.Name}}
  namespace: {{.Namespace}}
spec:
{{if eq .Type "acme"}}
  acme:
    server: {{.Server}}
    email: {{.Email}}
    autoRegistration: {{.AutoRegistration}}
    privateKeySecretRef:
      name: {{.Name}}-secret
      namespace: {{.Namespace}}
{{end}}
---
apiVersion: cert.gardener.cloud/v1alpha1
kind: Certificate
metadata:
  name: cert1
  namespace: {{.Namespace}}
spec:
  commonName: cert1.{{.Domain}}
  dnsNames:
  - cert1a.{{.Domain}}
  - cert1b.{{.Domain}}
  secretName: cert1-secret
  issuerRef:
    name: {{.Name}}
---
apiVersion: cert.gardener.cloud/v1alpha1
kind: Certificate
metadata:
  name: cert2
  namespace: {{.Namespace}}
spec:
  commonName: cert2.{{.Domain}}
  issuerRef:
    name: {{.Name}}
`

func init() {
	addIssuerTests(functestbasics)
}

func functestbasics(cfg *config.Config, iss *config.IssuerConfig) {
	_ = Describe("basics-"+iss.Name, func() {
		It("should work with "+iss.Name, func() {
			tmpl, err := template.New("Manifest").Parse(basicTemplate)
			Ω(err).Should(BeNil())

			basePath, err := os.Getwd()
			Ω(err).Should(BeNil())

			err = iss.CreateTempManifest(basePath, tmpl)
			defer iss.DeleteTempManifest()
			Ω(err).Should(BeNil())

			u := cfg.Utils

			err = u.AwaitKubectlGetCRDs("issuers.cert.gardener.cloud", "certificates.cert.gardener.cloud")
			Ω(err).Should(BeNil())

			err = u.KubectlApply(iss.TmpManifestFilename)
			Ω(err).Should(BeNil())

			err = u.AwaitIssuerReady(iss.Name)
			Ω(err).Should(BeNil())

			entryNames := []string{}
			for _, name := range []string{"1", "2"} {
				entryNames = append(entryNames, entryName(iss, name))
			}
			err = u.AwaitCertReady(entryNames...)
			Ω(err).Should(BeNil())

			itemMap, err := u.KubectlGetAllCertificates()
			Ω(err).Should(BeNil())

			Ω(itemMap).Should(MatchKeys(IgnoreExtras, Keys{
				entryName(iss, "1"): MatchKeys(IgnoreExtras, Keys{
					"metadata": MatchKeys(IgnoreExtras, Keys{
						"labels": MatchKeys(IgnoreExtras, Keys{
							"cert.gardener.cloud/certificate-hash": HavePrefix(""),
						}),
					}),
					"spec": MatchKeys(IgnoreExtras, Keys{
						"secretRef": MatchKeys(IgnoreExtras, Keys{
							"name":      HavePrefix(entryName(iss, "1") + "-"),
							"namespace": Equal(iss.Namespace),
						}),
					}),
					"status": MatchKeys(IgnoreExtras, Keys{
						"commonName":     Equal(dnsName(iss, "cert1")),
						"dnsNames":       And(HaveLen(2), ContainElement(dnsName(iss, "cert1a")), ContainElement(dnsName(iss, "cert1b"))),
						"state":          Equal("Ready"),
						"expirationDate": HavePrefix("20"),
					}),
				}),
				entryName(iss, "2"): MatchKeys(IgnoreExtras, Keys{
					"status": MatchKeys(IgnoreExtras, Keys{
						"commonName":     Equal(dnsName(iss, "cert2")),
						"state":          Equal("Ready"),
						"expirationDate": HavePrefix("20"),
					}),
				}),
			}))

			err = u.KubectlDelete(iss.TmpManifestFilename)
			Ω(err).Should(BeNil())

			err = u.AwaitCertDeleted(entryNames...)
			Ω(err).Should(BeNil())

			err = u.AwaitIssuerDeleted(iss.Name)
			Ω(err).Should(BeNil())
		})
	})
}

func dnsName(iss *config.IssuerConfig, name string) string {
	return name + "." + iss.Domain
}

func entryName(_ *config.IssuerConfig, name string) string {
	return "cert" + name
}

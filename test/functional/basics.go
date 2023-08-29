/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package functional

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"

	"github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/cert/legobridge"
	"github.com/gardener/cert-management/test/functional/config"
	"github.com/gardener/controller-manager-library/pkg/resources"
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
{{if not .PrivateKey }}
    autoRegistration: {{.AutoRegistration}}
{{end}}
    privateKeySecretRef:
      name: {{.Name}}-secret
      namespace: {{.Namespace}}
{{if .ExternalAccountBinding }}
    externalAccountBinding:
      keyID: {{ .ExternalAccountBinding.KeyID }}
      keySecretRef:
        name: {{.Name}}-eab-secret
        namespace: {{.Namespace}}    
{{end}}
{{if .SkipDNSChallengeValidation }}
    skipDNSChallengeValidation: true
{{end}}
{{end}}
{{if .ExternalAccountBinding }}
---
apiVersion: v1
kind: Secret
metadata:
  name: {{.Name}}-eab-secret
  namespace: {{.Namespace}}
type: Opaque
data:
  hmacKey: {{ .ExternalAccountBinding.HmacKey }}
{{end}}
{{if .PrivateKey }}
---
apiVersion: v1
kind: Secret
metadata:
  name: {{.Name}}-secret
  namespace: {{.Namespace}}
type: Opaque
data:
  privateKey: {{ .PrivateKey }}
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
---
apiVersion: cert.gardener.cloud/v1alpha1
kind: Certificate
metadata:
  name: cert2b
  namespace: {{.Namespace}}
spec:
  commonName: cert2.{{.Domain}}
  issuerRef:
    name: {{.Name}}
---
apiVersion: cert.gardener.cloud/v1alpha1
kind: Certificate
metadata:
  name: cert3
  namespace: {{.Namespace}}
spec:
  commonName: cert3.{{.Domain}}
  dnsNames:
  - "*.cert3.{{.Domain}}"
  issuerRef:
    name: {{.Name}}
  secretName: cert3-secret
  secretLabels:
    foo: bar
    some.gardener.cloud/thing: "true"
---
apiVersion: v1
kind: Secret
metadata:
  name: cert4-secret
  namespace: {{.Namespace}}
type: Opaque
---
apiVersion: cert.gardener.cloud/v1alpha1
kind: Certificate
metadata:
  name: cert4
  namespace: {{.Namespace}}
  labels:
    cert.gardener.cloud/hash: a74c0e0a617fd1499cddac5136b8e09e3ca30edd4f173f7e73d8910b
spec:
  commonName: cert4.{{.Domain}}
  secretName: cert4-secret
  issuerRef:
    name: {{.Name}}
`

var revoke2Template = `
apiVersion: cert.gardener.cloud/v1alpha1
kind: CertificateRevocation
metadata:
  name: revoke-cert2
  namespace: {{.Namespace}}
spec:
  certificateRef:
    name: cert2
    namespace: {{.Namespace}}
`

var revoke3Template = `
apiVersion: cert.gardener.cloud/v1alpha1
kind: CertificateRevocation
metadata:
  name: revoke-cert3
  namespace: {{.Namespace}}
spec:
  certificateRef:
    name: cert3
    namespace: {{.Namespace}}
  renew: true
`

var cert3WithKeystores = `
apiVersion: v1
kind: Secret
metadata:
  name: keystore-password
  namespace: {{.Namespace}}
data:
  password: cGFzcw== # pass
---
apiVersion: cert.gardener.cloud/v1alpha1
kind: Certificate
metadata:
  name: cert3
  namespace: {{.Namespace}}
spec:
  commonName: cert3.{{.Domain}}
  dnsNames:
  - "*.cert3.{{.Domain}}"
  issuerRef:
    name: {{.Name}}
  keystores:
    jks:
      create: true
      passwordSecretRef:
        key: password
        secretName: keystore-password
    pkcs12:
      create: true
      passwordSecretRef:
        key: password
        secretName: keystore-password
  secretName: cert3-secret
`

func init() {
	resources.Register(v1alpha1.SchemeBuilder)
	addIssuerTests(functestbasics)
}

func functestbasics(cfg *config.Config, iss *config.IssuerConfig) {
	_ = Describe("basics-"+iss.Name, func() {
		It("should work with "+iss.Name, func() {
			manifestFilename, err := iss.CreateTempManifest("Manifest", basicTemplate)
			defer iss.DeleteTempManifest(manifestFilename)
			Ω(err).Should(BeNil())

			u := cfg.Utils

			err = u.AwaitKubectlGetCRDs("issuers.cert.gardener.cloud", "certificates.cert.gardener.cloud")
			Ω(err).Should(BeNil())

			err = u.KubectlApply(manifestFilename)
			Ω(err).Should(BeNil())

			err = u.AwaitIssuerReady(iss.Name)
			Ω(err).Should(BeNil())

			entryNames := []string{}
			for _, name := range []string{"1", "2", "2b", "3"} {
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
							"cert.gardener.cloud/hash": HavePrefix(""),
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
				entryName(iss, "2b"): MatchKeys(IgnoreExtras, Keys{
					"status": MatchKeys(IgnoreExtras, Keys{
						"commonName":     Equal(dnsName(iss, "cert2")),
						"state":          Equal("Ready"),
						"expirationDate": HavePrefix("20"),
					}),
				}),
				entryName(iss, "3"): MatchKeys(IgnoreExtras, Keys{
					"status": MatchKeys(IgnoreExtras, Keys{
						"commonName":     Equal(dnsName(iss, "cert3")),
						"dnsNames":       And(HaveLen(1), ContainElement(dnsName(iss, "*.cert3"))),
						"state":          Equal("Ready"),
						"expirationDate": HavePrefix("20"),
					}),
				}),
			}))

			By("check keystores in cert3", func() {
				secret, err := u.KubectlGetSecret("cert3-secret")
				Ω(err).Should(BeNil())
				Ω(len(secret.Data)).Should(Equal(3))

				manifestFilename, err := iss.CreateTempManifest("Manifest", cert3WithKeystores)
				defer iss.DeleteTempManifest(manifestFilename)
				Ω(err).Should(BeNil())
				err = u.KubectlApply(manifestFilename)
				Ω(err).Should(BeNil())

				time.Sleep(3 * time.Second) // wait for reconciliation

				secret, err = u.KubectlGetSecret("cert3-secret")
				Ω(len(secret.Data)).Should(Equal(7))
				Ω(secret.Data[legobridge.JKSTruststoreKey]).ShouldNot(BeNil())
				Ω(secret.Data[legobridge.JKSSecretKey]).ShouldNot(BeNil())
				Ω(secret.Data[legobridge.PKCS12TruststoreKey]).ShouldNot(BeNil())
				Ω(secret.Data[legobridge.PKCS12SecretKey]).ShouldNot(BeNil())
			})

			By("check secret labels in cert3", func() {
				secret, err := u.KubectlGetSecret("cert3-secret")
				Ω(err).Should(BeNil())
				Ω(secret.Labels["foo"]).Should(Equal("bar"))
				Ω(secret.Labels["some.gardener.cloud/thing"]).Should(Equal("true"))
			})

			By("check starting from invalid state in cert4", func() {
				err = u.AwaitCertReady("cert4")
				Ω(err).Should(BeNil())
			})

			By("revoking without renewal", func() {
				// need to wait 30 seconds after certificate creation because of time drift (see func WasRequestedBefore() for details)
				time.Sleep(30 * time.Second)

				filename, err := iss.CreateTempManifest("revoke2", revoke2Template)
				defer iss.DeleteTempManifest(filename)
				Ω(err).Should(BeNil())

				err = u.KubectlApply(filename)
				Ω(err).Should(BeNil())

				err = u.AwaitCertRevocationApplied("revoke-cert2")
				Ω(err).Should(BeNil())

				err = u.AwaitCertRevoked(entryName(iss, "2"), entryName(iss, "2b"))
				Ω(err).Should(BeNil())

				err = u.KubectlDelete(filename)
				Ω(err).Should(BeNil())
			})

			if !iss.SkipRevokeWithRenewal {
				By("revoking with renewal", func() {
					filename, err := iss.CreateTempManifest("revoke3", revoke3Template)
					defer iss.DeleteTempManifest(filename)
					Ω(err).Should(BeNil())

					err = u.KubectlApply(filename)
					Ω(err).Should(BeNil())

					err = u.AwaitCertRevocationApplied("revoke-cert3")
					Ω(err).Should(BeNil())

					err = u.AwaitCertReady(entryName(iss, "3"))
					Ω(err).Should(BeNil())

					err = u.KubectlDelete(filename)
					Ω(err).Should(BeNil())
				})
			}

			err = u.KubectlDelete(manifestFilename)
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

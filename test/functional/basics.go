/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package functional

import (
	"context"
	"crypto/x509"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"

	"github.com/gardener/cert-management/pkg/cert/legobridge"
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
{{if not .PrivateKey }}
    autoRegistration: {{.AutoRegistration}}
{{end}}
    precheckNameservers:
{{range .PrecheckNameservers }}
    - {{.}}
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
---
apiVersion: cert.gardener.cloud/v1alpha1
kind: Certificate
metadata:
  name: cert5
  namespace: {{.Namespace}}
spec:
  commonName: 
  dnsNames:
  - cert5.very-very-very-very-very-very-very-very-very-very-very-long.{{.Domain}} # more than 64 chars
  - cert5.{{.Domain}}
  secretName: cert5-secret
  issuerRef:
    name: {{.Name}}
---
apiVersion: cert.gardener.cloud/v1alpha1
kind: Certificate
metadata:
  name: cert6
  namespace: {{.Namespace}}
spec:
  commonName: cert6.{{.Domain}}
  secretName: cert6-secret
  issuerRef:
    name: {{.Name}}
  privateKey:
    algorithm: RSA
    size: 3072
---
apiVersion: cert.gardener.cloud/v1alpha1
kind: Certificate
metadata:
  name: cert7
  namespace: {{.Namespace}}
spec:
  commonName: cert7.{{.Domain}}
  secretName: cert7-secret
  issuerRef:
    name: {{.Name}}
  privateKey:
    algorithm: RSA
    size: 4096
---
apiVersion: cert.gardener.cloud/v1alpha1
kind: Certificate
metadata:
  name: cert8
  namespace: {{.Namespace}}
spec:
  commonName: cert8.{{.Domain}}
  secretName: cert8-secret
  issuerRef:
    name: {{.Name}}
  privateKey:
    algorithm: ECDSA
    size: 256
---
apiVersion: cert.gardener.cloud/v1alpha1
kind: Certificate
metadata:
  name: cert9
  namespace: {{.Namespace}}
spec:
  commonName: cert9.{{.Domain}}
  secretName: cert9-secret
  issuerRef:
    name: {{.Name}}
  privateKey:
    algorithm: ECDSA
    size: 384
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
	addIssuerTests(functestbasics)
}

func functestbasics(cfg *config.Config, iss *config.IssuerConfig) {
	_ = Describe("basics-"+iss.Name, func() {
		It("should work with "+iss.Name, func(ctx context.Context) {
			if useDNSRecords() {
				Skip("skipping for DNSRecords")
			}
			manifestFilename, err := iss.CreateTempManifest("Manifest", basicTemplate)
			defer iss.DeleteTempManifest(manifestFilename)
			Expect(err).ShouldNot(HaveOccurred())

			u := cfg.Utils

			err = u.WaitUntilCRDsReady(ctx, "issuers.cert.gardener.cloud", "certificates.cert.gardener.cloud")
			Expect(err).ShouldNot(HaveOccurred())

			err = u.KubectlApply(manifestFilename)
			Expect(err).ShouldNot(HaveOccurred())

			err = u.WaitUntilIssuerReady(ctx, iss.Name)
			if err != nil {
				output, _ := u.KubectlGetAllIssuers()
				println("all issuers:")
				println(output)
			}
			Expect(err).ShouldNot(HaveOccurred())

			entryNames := []string{}
			for _, name := range []string{"1", "2", "2b", "3", "5", "6", "7", "8", "9"} {
				entryNames = append(entryNames, entryName(iss, name))
			}
			err = u.WaitUntilCertReady(ctx, entryNames...)
			if err != nil {
				output, _ := u.KubectlGetAllCertificatesPlain()
				println("all certs:")
				println(output)
			}
			Expect(err).ShouldNot(HaveOccurred())

			certMap, err := u.GetAllCertificates(ctx)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(certMap).Should(MatchKeys(IgnoreExtras, Keys{
				entryName(iss, "1"): MatchFields(IgnoreExtras, Fields{
					"ObjectMeta": MatchFields(IgnoreExtras, Fields{
						"Labels": MatchKeys(IgnoreExtras, Keys{
							"cert.gardener.cloud/hash": HavePrefix(""),
						}),
					}),
					"Spec": MatchFields(IgnoreExtras, Fields{
						"SecretRef": PointTo(MatchFields(IgnoreExtras, Fields{
							"Name":      HavePrefix(entryName(iss, "1") + "-"),
							"Namespace": Equal(iss.Namespace),
						})),
					}),
					"Status": MatchFields(IgnoreExtras, Fields{
						"CommonName":     PointTo(Equal(dnsName(iss, "cert1"))),
						"DNSNames":       And(HaveLen(2), ContainElement(dnsName(iss, "cert1a")), ContainElement(dnsName(iss, "cert1b"))),
						"State":          Equal("Ready"),
						"ExpirationDate": PointTo(HavePrefix("20")),
					}),
				}),
				entryName(iss, "2"): MatchFields(IgnoreExtras, Fields{
					"Status": MatchFields(IgnoreExtras, Fields{
						"CommonName":     PointTo(Equal(dnsName(iss, "cert2"))),
						"State":          Equal("Ready"),
						"ExpirationDate": PointTo(HavePrefix("20")),
					}),
				}),
				entryName(iss, "2b"): MatchFields(IgnoreExtras, Fields{
					"Status": MatchFields(IgnoreExtras, Fields{
						"CommonName":     PointTo(Equal(dnsName(iss, "cert2"))),
						"State":          Equal("Ready"),
						"ExpirationDate": PointTo(HavePrefix("20")),
					}),
				}),
				entryName(iss, "3"): MatchFields(IgnoreExtras, Fields{
					"Status": MatchFields(IgnoreExtras, Fields{
						"CommonName":     PointTo(Equal(dnsName(iss, "cert3"))),
						"DNSNames":       And(HaveLen(1), ContainElement(dnsName(iss, "*.cert3"))),
						"State":          Equal("Ready"),
						"ExpirationDate": PointTo(HavePrefix("20")),
					}),
				}),
				entryName(iss, "5"): MatchFields(IgnoreExtras, Fields{
					"Status": MatchFields(IgnoreExtras, Fields{
						"DNSNames":       And(HaveLen(2), ContainElements(dnsName(iss, "cert5.very-very-very-very-very-very-very-very-very-very-very-long"), dnsName(iss, "cert5"))),
						"State":          Equal("Ready"),
						"ExpirationDate": PointTo(HavePrefix("20")),
					}),
				}),
				entryName(iss, "6"): MatchFields(IgnoreExtras, Fields{
					"Status": MatchFields(IgnoreExtras, Fields{
						"CommonName":     PointTo(Equal(dnsName(iss, "cert6"))),
						"State":          Equal("Ready"),
						"ExpirationDate": PointTo(HavePrefix("20")),
					}),
				}),
				entryName(iss, "7"): MatchFields(IgnoreExtras, Fields{
					"Status": MatchFields(IgnoreExtras, Fields{
						"CommonName":     PointTo(Equal(dnsName(iss, "cert7"))),
						"State":          Equal("Ready"),
						"ExpirationDate": PointTo(HavePrefix("20")),
					}),
				}),
				entryName(iss, "8"): MatchFields(IgnoreExtras, Fields{
					"Status": MatchFields(IgnoreExtras, Fields{
						"CommonName":     PointTo(Equal(dnsName(iss, "cert8"))),
						"State":          Equal("Ready"),
						"ExpirationDate": PointTo(HavePrefix("20")),
					}),
				}),
				entryName(iss, "9"): MatchFields(IgnoreExtras, Fields{
					"Status": MatchFields(IgnoreExtras, Fields{
						"CommonName":     PointTo(Equal(dnsName(iss, "cert9"))),
						"State":          Equal("Ready"),
						"ExpirationDate": PointTo(HavePrefix("20")),
					}),
				}),
			}))

			Expect(u.CheckCertificatePrivateKey("cert3-secret", x509.RSA, 2048)).ShouldNot(HaveOccurred())
			Expect(u.CheckCertificatePrivateKey("cert6-secret", x509.RSA, 3072)).ShouldNot(HaveOccurred())
			Expect(u.CheckCertificatePrivateKey("cert7-secret", x509.RSA, 4096)).ShouldNot(HaveOccurred())
			Expect(u.CheckCertificatePrivateKey("cert8-secret", x509.ECDSA, 256)).ShouldNot(HaveOccurred())
			Expect(u.CheckCertificatePrivateKey("cert9-secret", x509.ECDSA, 384)).ShouldNot(HaveOccurred())

			By("check keystores in cert3", func() {
				secret, err := u.GetSecret("cert3-secret")
				Expect(err).ShouldNot(HaveOccurred())
				Expect(secret.Data).Should(HaveLen(3))

				manifestFilename, err := iss.CreateTempManifest("Manifest", cert3WithKeystores)
				defer iss.DeleteTempManifest(manifestFilename)
				Expect(err).ShouldNot(HaveOccurred())
				err = u.KubectlApply(manifestFilename)
				Expect(err).ShouldNot(HaveOccurred())

				time.Sleep(3 * time.Second) // wait for reconciliation

				secret, err = u.GetSecret("cert3-secret")
				Expect(err).ShouldNot(HaveOccurred())
				Expect(secret.Data).Should(HaveLen(7))
				Expect(secret.Data[legobridge.JKSTruststoreKey]).ShouldNot(BeNil())
				Expect(secret.Data[legobridge.JKSSecretKey]).ShouldNot(BeNil())
				Expect(secret.Data[legobridge.PKCS12TruststoreKey]).ShouldNot(BeNil())
				Expect(secret.Data[legobridge.PKCS12SecretKey]).ShouldNot(BeNil())
			})

			By("check secret labels in cert3", func() {
				secret, err := u.GetSecret("cert3-secret")
				Expect(err).ShouldNot(HaveOccurred())
				Expect(secret.Labels["foo"]).Should(Equal("bar"))
				Expect(secret.Labels["some.gardener.cloud/thing"]).Should(Equal("true"))
			})

			By("check starting from invalid state in cert4", func() {
				err = u.WaitUntilCertReady(ctx, "cert4")
				Expect(err).ShouldNot(HaveOccurred())
			})

			By("revoking without renewal", func() {
				// need to wait 30 seconds after certificate creation because of time drift (see func WasRequestedBefore() for details)
				time.Sleep(30 * time.Second)

				filename, err := iss.CreateTempManifest("revoke2", revoke2Template)
				defer iss.DeleteTempManifest(filename)
				Expect(err).ShouldNot(HaveOccurred())

				err = u.KubectlApply(filename)
				Expect(err).ShouldNot(HaveOccurred())

				err = u.WaitUntilCertRevocationApplied(ctx, "revoke-cert2")
				Expect(err).ShouldNot(HaveOccurred())

				err = u.WaitUntilCertRevoked(ctx, entryName(iss, "2"), entryName(iss, "2b"))
				Expect(err).ShouldNot(HaveOccurred())

				err = u.KubectlDelete(filename)
				Expect(err).ShouldNot(HaveOccurred())
			})

			if !iss.SkipRevokeWithRenewal {
				By("revoking with renewal", func() {
					filename, err := iss.CreateTempManifest("revoke3", revoke3Template)
					defer iss.DeleteTempManifest(filename)
					Expect(err).ShouldNot(HaveOccurred())

					err = u.KubectlApply(filename)
					Expect(err).ShouldNot(HaveOccurred())

					err = u.WaitUntilCertRevocationApplied(ctx, "revoke-cert3")
					Expect(err).ShouldNot(HaveOccurred())

					err = u.WaitUntilCertReady(ctx, entryName(iss, "3"))
					Expect(err).ShouldNot(HaveOccurred())

					err = u.KubectlDelete(filename)
					Expect(err).ShouldNot(HaveOccurred())
				})
			}

			err = u.KubectlDelete(manifestFilename)
			Expect(err).ShouldNot(HaveOccurred())

			err = u.WaitUntilCertDeleted(ctx, entryNames...)
			Expect(err).ShouldNot(HaveOccurred())

			err = u.WaitUntilIssuerDeleted(ctx, iss.Name)
			Expect(err).ShouldNot(HaveOccurred())
		}, SpecTimeout(360*time.Second))
	})
}

func dnsName(iss *config.IssuerConfig, name string) string {
	return name + "." + iss.Domain
}

func entryName(_ *config.IssuerConfig, name string) string {
	return "cert" + name
}

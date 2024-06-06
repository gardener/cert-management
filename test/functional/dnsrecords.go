/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package functional

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/test/functional/config"
	dnsapi "github.com/gardener/external-dns-management/pkg/apis/dns/v1alpha1"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/controllerutils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/kube-openapi/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/controller-manager-library/pkg/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
)

var dnsrecordsTemplate = `
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
  annotations:
    cert.gardener.cloud/dnsrecord-provider-type: dummy-type
    cert.gardener.cloud/dnsrecord-secret-ref: dummy-ref
spec:
  commonName: cert1.{{.Domain}}
  dnsNames:
  - cert1a.{{.Domain}}
  - cert1b.{{.Domain}}
  secretName: cert1-secret
  issuerRef:
    name: {{.Name}}
`

func init() {
	utils.Must(resources.Register(v1alpha1.SchemeBuilder))
	utils.Must(resources.Register(extensionsv1alpha.SchemeBuilder))
	utils.Must(resources.Register(dnsapi.SchemeBuilder))
	addIssuerTests(functestdnsrecords)
}

func functestdnsrecords(cfg *config.Config, iss *config.IssuerConfig) {
	_ = Describe("basics-"+iss.Name, Ordered, func() {
		var cancelFuncTranslator context.CancelFunc
		BeforeAll(func() {
			cancelFuncTranslator = startDNSRecordToDNSEntryTranslator("default", cfg.DNSKubeConfig)
		})
		AfterAll(func() {
			if cancelFuncTranslator != nil {
				cancelFuncTranslator()
			}
		})
		It("should work with "+iss.Name, func(_ context.Context) {
			if os.Getenv("USE_DNSRECORDS") != "true" {
				Skip("skipping as not using DNSRecords")
			}
			manifestFilename, err := iss.CreateTempManifest("Manifest", dnsrecordsTemplate)
			defer iss.DeleteTempManifest(manifestFilename)
			Ω(err).ShouldNot(HaveOccurred())

			u := cfg.Utils

			err = u.AwaitKubectlGetCRDs("issuers.cert.gardener.cloud", "certificates.cert.gardener.cloud")
			Ω(err).ShouldNot(HaveOccurred())

			err = u.KubectlApply(manifestFilename)
			Ω(err).ShouldNot(HaveOccurred())

			err = u.AwaitIssuerReady(iss.Name)
			Ω(err).ShouldNot(HaveOccurred())

			cert1Name := entryName(iss, "1")
			err = u.AwaitCertReady(cert1Name)
			Ω(err).ShouldNot(HaveOccurred())

			itemMap, err := u.KubectlGetAllCertificates()
			Ω(err).ShouldNot(HaveOccurred())

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
			}))

			err = u.KubectlDelete(manifestFilename)
			Ω(err).ShouldNot(HaveOccurred())

			err = u.AwaitCertDeleted(cert1Name)
			Ω(err).ShouldNot(HaveOccurred())

			err = u.AwaitIssuerDeleted(iss.Name)
			Ω(err).ShouldNot(HaveOccurred())
		}, SpecTimeout(180*time.Second))
	})
}

func startDNSRecordToDNSEntryTranslator(namespace, dnskubeconfig string) context.CancelFunc {
	var collectedErrors []error

	reportError := func(description string, err error) {
		collectedErrors = append(collectedErrors, err)
		println(description, "failed with:", err.Error())
	}

	config, err := clientcmd.BuildConfigFromFlags("", dnskubeconfig)
	if err != nil {
		reportError("BuildConfigFromFlags", err)
	}

	c, err := client.New(config, client.Options{
		Scheme: resources.DefaultScheme(),
	})
	if err != nil {
		reportError("client.New", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	entries := map[string]*dnsapi.DNSEntry{}
	go func() {
		for {
			select {
			case <-ctx.Done():
				if len(collectedErrors) > 0 {
					panic(errors.Join(collectedErrors...))
				}
				return
			default:
			}

			list := &extensionsv1alpha.DNSRecordList{}
			if err := c.List(ctx, list, client.InNamespace(namespace)); err != nil {
				reportError("List DNSRecords", err)
			}

			found := sets.String{}
			for _, record := range list.Items {
				if record.Spec.Type != "dummy-type" ||
					record.Spec.SecretRef.Name != "dummy-ref" ||
					record.Spec.SecretRef.Namespace != namespace ||
					record.Spec.RecordType != extensionsv1alpha.DNSRecordTypeTXT {
					println("ignoring", record.Name)
					continue
				}
				found.Insert(record.Name)
				if entry := entries[record.Name]; entry == nil {
					println("create", record.Name)
					if err := addFinalizer(ctx, c, record); err != nil {
						reportError("addFinalizer", err)
					}
					if entry, err := createDNSEntry(ctx, c, record); err != nil {
						reportError("createDNSEntry", err)
					} else {
						entries[record.Name] = entry
					}
				} else if record.DeletionTimestamp != nil {
					if err := c.Delete(ctx, entry); err != nil {
						reportError("delete DNSEntry", err)
					} else {
						delete(entries, record.Name)
					}
					if err := removeFinalizer(ctx, c, record); err != nil {
						reportError("removeFinalizer", err)
					}
				} else {
					entry := &dnsapi.DNSEntry{}
					if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: record.Name}, entry); err != nil {
						reportError("get DNSEntry", err)
					}
					if entry.Generation == entry.Status.ObservedGeneration && record.Status.LastOperation == nil {
						switch entry.Status.State {
						case "Ready":
							record.Status.LastOperation = &v1beta1.LastOperation{
								Description:    "ready",
								LastUpdateTime: metav1.Now(),
								Progress:       100,
								State:          "Succeeded",
								Type:           "Create",
							}
						case "Error":
							record.Status.LastOperation = &v1beta1.LastOperation{
								Description:    "failed",
								LastUpdateTime: metav1.Now(),
								Progress:       100,
								State:          "Error",
								Type:           "Create",
							}
						}
						if record.Status.LastOperation != nil {
							if err := c.Status().Update(ctx, &record); err != nil {
								reportError("record status update", err)
							}
						}
					}
				}
			}

			for name, entry := range entries {
				if found.Has(name) {
					continue
				}
				if err := c.Delete(ctx, entry); err != nil {
					reportError("delete DNSEntry (cleanup)", err)
				}
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()
	println("startDNSRecordToDNSEntryTranslator started")
	return cancel
}

func addFinalizer(ctx context.Context, c client.Client, record extensionsv1alpha.DNSRecord) error {
	return controllerutils.AddFinalizers(ctx, c, &record, "cert.gardener.cloud/test")
}

func removeFinalizer(ctx context.Context, c client.Client, record extensionsv1alpha.DNSRecord) error {
	return controllerutils.RemoveFinalizers(ctx, c, &record, "cert.gardener.cloud/test")
}

func createDNSEntry(ctx context.Context, c client.Client, record extensionsv1alpha.DNSRecord) (*dnsapi.DNSEntry, error) {
	entry := &dnsapi.DNSEntry{
		ObjectMeta: metav1.ObjectMeta{
			Name:      record.Name,
			Namespace: record.Namespace,
		},
		Spec: dnsapi.DNSEntrySpec{
			DNSName: record.Spec.Name,
			Text:    record.Spec.Values,
		},
	}
	err := c.Create(ctx, entry)
	return entry, err
}

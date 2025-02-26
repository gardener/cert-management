/*
 * SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package core

import (
	"github.com/Masterminds/semver/v3"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/controller-manager-library/pkg/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	certutils "github.com/gardener/cert-management/pkg/cert/utils"
)

const (
	defaultClusterID              = "default-cluster"
	targetClusterID               = "target-cluster"
	defaultClusterIssuerNamespace = "issuer-namespace"
	defaultIssuerName             = "default-issuer"
	namespace1                    = "ns1"
)

var issuerGroupKind = resources.NewGroupKind(api.GroupName, api.IssuerKind)

var _ = Describe("Support", func() {
	defaultIssuer := resources.NewClusterKey(defaultClusterID, issuerGroupKind, defaultClusterIssuerNamespace, defaultIssuerName)
	issuer1c := resources.NewClusterKey(defaultClusterID, issuerGroupKind, defaultClusterIssuerNamespace, "issuer1")
	issuer1t := resources.NewClusterKey(targetClusterID, issuerGroupKind, namespace1, "issuer1")
	issuer2t := resources.NewClusterKey(targetClusterID, issuerGroupKind, namespace1, "issuer2")
	issuer1t2 := resources.NewClusterKey(targetClusterID, issuerGroupKind, "bar", "issuer1")
	sel1c := &api.DNSSelection{Include: []string{"example.com"}}
	sel1t := &api.DNSSelection{Include: []string{"sel1t.example.com"}}
	sel2t := &api.DNSSelection{Include: []string{"sel2t.example.com"}}
	sel1t2 := &api.DNSSelection{Include: []string{"sub.sel1t.example.com"}}
	Context("FindIssuerKeyByName", func() {
		It("", func() {
			support := newSupport()
			support.AddIssuerDomains(issuer1c, sel1c)
			support.AddIssuerDomains(issuer2t, sel2t)

			key := support.FindIssuerKeyByName("foo", "issuer1")
			Expect(key.Name()).To(Equal("issuer1"))
			Expect(key.Cluster()).To(Equal(certutils.ClusterDefault))

			key = support.FindIssuerKeyByName("foo", "issuer2")
			Expect(key.Name()).To(Equal("issuer2"))
			Expect(key.Cluster()).To(Equal(certutils.ClusterTarget))
			Expect(key.Namespace()).To(Equal(namespace1))

			support.AddIssuerDomains(issuer1t, sel1t)
			key = support.FindIssuerKeyByName("foo", "issuer1")
			Expect(key.Name()).To(Equal("issuer1"))
			Expect(key.Cluster()).To(Equal(certutils.ClusterTarget))
			Expect(key.Namespace()).To(Equal(namespace1))

			support.AddIssuerDomains(issuer1t2, sel1t2)
			key = support.FindIssuerKeyByName("bar", "issuer1")
			Expect(key.Name()).To(Equal("issuer1"))
			Expect(key.Cluster()).To(Equal(certutils.ClusterTarget))
			Expect(key.Namespace()).To(Equal("bar"))

			key = support.FindIssuerKeyByName(namespace1, "issuer1")
			Expect(key.Name()).To(Equal("issuer1"))
			Expect(key.Cluster()).To(Equal(certutils.ClusterTarget))
			Expect(key.Namespace()).To(Equal(namespace1))
		})
	})

	Context("FindIssuerKeyByBestMatch", func() {
		It("", func() {
			support := newSupport()
			support.AddIssuerDomains(defaultIssuer, nil)
			support.AddIssuerDomains(issuer1c, sel1c)
			support.AddIssuerDomains(issuer1t, sel1t)
			support.AddIssuerDomains(issuer1t2, sel1t2)

			key := support.FindIssuerKeyByBestMatch([]string{"foo.com"})
			Expect(key).NotTo(BeNil())
			Expect(key.Name()).To(Equal(defaultIssuerName))
			Expect(key.Cluster()).To(Equal(certutils.ClusterDefault))

			key = support.FindIssuerKeyByBestMatch([]string{"foo.example.com"})
			Expect(key.Name()).To(Equal("issuer1"))
			Expect(key.Cluster()).To(Equal(certutils.ClusterDefault))

			key = support.FindIssuerKeyByBestMatch([]string{"foo.bar.sel1t.example.com"})
			Expect(key.Name()).To(Equal("issuer1"))
			Expect(key.Cluster()).To(Equal(certutils.ClusterTarget))
			Expect(key.Namespace()).To(Equal(namespace1))

			key = support.FindIssuerKeyByBestMatch([]string{"foo.sub.sel1t.example.com"})
			Expect(key.Name()).To(Equal("issuer1"))
			Expect(key.Cluster()).To(Equal(certutils.ClusterTarget))
			Expect(key.Namespace()).To(Equal("bar"))
		})
	})

	Context("IssuerClusterObjectKey", func() {
		support := newSupport()
		support.AddIssuerDomains(defaultIssuer, nil)
		support.AddIssuerDomains(issuer1c, sel1c)
		support.AddIssuerDomains(issuer1t, sel1t)

		spec := &api.CertificateSpec{
			CommonName: ptr.To("foo.example.com"),
		}
		key := support.IssuerClusterObjectKey("foo", spec)
		Expect(key.Name()).To(Equal("issuer1"))
		Expect(key.Cluster()).To(Equal(certutils.ClusterDefault))

		spec2 := &api.CertificateSpec{
			CommonName: ptr.To("foo.sel1t.example.com"),
		}
		key = support.IssuerClusterObjectKey("foo", spec2)
		Expect(key.Name()).To(Equal("issuer1"))
		Expect(key.Cluster()).To(Equal(certutils.ClusterTarget))
		Expect(key.Namespace()).To(Equal(namespace1))

		spec2b := &api.CertificateSpec{
			DNSNames: []string{"foo.sel1t.example.com"},
		}
		key = support.IssuerClusterObjectKey("foo", spec2b)
		Expect(key.Name()).To(Equal("issuer1"))
		Expect(key.Cluster()).To(Equal(certutils.ClusterTarget))
		Expect(key.Namespace()).To(Equal(namespace1))

		spec3 := &api.CertificateSpec{
			CommonName: ptr.To("bar.example.com"),
			IssuerRef: &api.IssuerRef{
				Name:      "issuer1",
				Namespace: namespace1,
			},
		}
		key = support.IssuerClusterObjectKey("foo", spec3)
		Expect(key.Name()).To(Equal("issuer1"))
		Expect(key.Cluster()).To(Equal(certutils.ClusterTarget))
		Expect(key.Namespace()).To(Equal(namespace1))

		support.RemoveIssuer(issuer1c)
		key = support.IssuerClusterObjectKey("foo", spec)
		Expect(key.Name()).To(Equal(defaultIssuerName))
		Expect(key.Cluster()).To(Equal(certutils.ClusterDefault))

		// unknown issuer
		spec4 := &api.CertificateSpec{
			CommonName: ptr.To("bar.example.com"),
			IssuerRef: &api.IssuerRef{
				Name:      "issuer-bar",
				Namespace: "foo",
			},
		}
		key = support.IssuerClusterObjectKey("foo2", spec4)
		Expect(key.Name()).To(Equal("issuer-bar"))
		Expect(key.Cluster()).To(Equal(certutils.ClusterTarget))
		Expect(key.Namespace()).To(Equal("foo"))
	})
})

func newSupport() *Support {
	return &Support{
		state:             newState(),
		defaultCluster:    &testCluster{id: defaultClusterID},
		targetCluster:     &testCluster{id: targetClusterID},
		defaultIssuerName: defaultIssuerName,
		issuerNamespace:   defaultClusterIssuerNamespace,
	}
}

type testCluster struct {
	id string
}

var _ resources.Cluster = &testCluster{}

func (t testCluster) Resources() resources.Resources {
	panic("unsupported")
}

func (t testCluster) GetCluster() resources.Cluster {
	panic("unsupported")
}

func (t testCluster) GetServerVersion() *semver.Version {
	panic("unsupported")
}

func (t testCluster) GetName() string {
	panic("unsupported")
}

func (t testCluster) GetId() string {
	return t.id
}

func (t testCluster) GetMigrationIds() utils.StringSet {
	panic("unsupported")
}

func (t testCluster) Config() rest.Config {
	panic("unsupported")
}

func (t testCluster) GetAttr(_ interface{}) interface{} {
	panic("unsupported")
}

func (t testCluster) SetAttr(_, _ interface{}) {
	panic("unsupported")
}

// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	context "context"

	certv1alpha1 "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	scheme "github.com/gardener/cert-management/pkg/client/cert/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// CertificatesGetter has a method to return a CertificateInterface.
// A group's client should implement this interface.
type CertificatesGetter interface {
	Certificates(namespace string) CertificateInterface
}

// CertificateInterface has methods to work with Certificate resources.
type CertificateInterface interface {
	Create(ctx context.Context, certificate *certv1alpha1.Certificate, opts v1.CreateOptions) (*certv1alpha1.Certificate, error)
	Update(ctx context.Context, certificate *certv1alpha1.Certificate, opts v1.UpdateOptions) (*certv1alpha1.Certificate, error)
	// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
	UpdateStatus(ctx context.Context, certificate *certv1alpha1.Certificate, opts v1.UpdateOptions) (*certv1alpha1.Certificate, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*certv1alpha1.Certificate, error)
	List(ctx context.Context, opts v1.ListOptions) (*certv1alpha1.CertificateList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *certv1alpha1.Certificate, err error)
	CertificateExpansion
}

// certificates implements CertificateInterface
type certificates struct {
	*gentype.ClientWithList[*certv1alpha1.Certificate, *certv1alpha1.CertificateList]
}

// newCertificates returns a Certificates
func newCertificates(c *CertV1alpha1Client, namespace string) *certificates {
	return &certificates{
		gentype.NewClientWithList[*certv1alpha1.Certificate, *certv1alpha1.CertificateList](
			"certificates",
			c.RESTClient(),
			scheme.ParameterCodec,
			namespace,
			func() *certv1alpha1.Certificate { return &certv1alpha1.Certificate{} },
			func() *certv1alpha1.CertificateList { return &certv1alpha1.CertificateList{} },
		),
	}
}

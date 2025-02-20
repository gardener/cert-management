// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	context "context"
	time "time"

	apiscertv1alpha1 "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	versioned "github.com/gardener/cert-management/pkg/client/cert/clientset/versioned"
	internalinterfaces "github.com/gardener/cert-management/pkg/client/cert/informers/externalversions/internalinterfaces"
	certv1alpha1 "github.com/gardener/cert-management/pkg/client/cert/listers/cert/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// CertificateRevocationInformer provides access to a shared informer and lister for
// CertificateRevocations.
type CertificateRevocationInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() certv1alpha1.CertificateRevocationLister
}

type certificateRevocationInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewCertificateRevocationInformer constructs a new informer for CertificateRevocation type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewCertificateRevocationInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredCertificateRevocationInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredCertificateRevocationInformer constructs a new informer for CertificateRevocation type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredCertificateRevocationInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CertV1alpha1().CertificateRevocations(namespace).List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CertV1alpha1().CertificateRevocations(namespace).Watch(context.TODO(), options)
			},
		},
		&apiscertv1alpha1.CertificateRevocation{},
		resyncPeriod,
		indexers,
	)
}

func (f *certificateRevocationInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredCertificateRevocationInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *certificateRevocationInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&apiscertv1alpha1.CertificateRevocation{}, f.defaultInformer)
}

func (f *certificateRevocationInformer) Lister() certv1alpha1.CertificateRevocationLister {
	return certv1alpha1.NewCertificateRevocationLister(f.Informer().GetIndexer())
}

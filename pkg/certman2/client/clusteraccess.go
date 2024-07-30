package client

import (
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/go-logr/logr"
)

// ClusterAccess contains clients for various connected Kubernetes clusters.
type ClusterAccess struct {
	mainClientSet   kubernetes.Interface
	issuerClientSet kubernetes.Interface
	dnsClientSet    kubernetes.Interface
}

// NewClusterAccess returns a new instance of ClusterAccess for all clusters.
func NewClusterAccess(log logr.Logger, main, issuer, dns kubernetes.Interface) *ClusterAccess {
	if issuer == nil {
		issuer = main
		log.Info("using main cluster for provided issuers")
		if dns == nil {
			dns = main
			log.Info("using main cluster for DNS resources")
		}
	} else if dns == nil {
		dns = issuer
		log.Info("using issuer cluster for DNS resources")
	}

	return &ClusterAccess{
		mainClientSet:   main,
		issuerClientSet: issuer,
		dnsClientSet:    dns,
	}
}

// MainClientSet returns client set for the main cluster containing certificate and source resources.
func (a *ClusterAccess) MainClientSet() kubernetes.Interface {
	return a.mainClientSet
}

// IssuerClientSet returns client set for the cluster containing provided issuers.
func (a *ClusterAccess) IssuerClientSet() kubernetes.Interface {
	return a.issuerClientSet
}

// DNSClientSet returns client set for the cluster used for DNSEntries or DNSRecords.
func (a *ClusterAccess) DNSClientSet() kubernetes.Interface {
	return a.dnsClientSet
}

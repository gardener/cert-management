package client

import (
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ClusterAccess contains clients for various connected Kubernetes clusters.
type ClusterAccess struct {
	mainClient   client.Client
	issuerClient client.Client
	dnsClient    client.Client
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
		mainClient:   main.Client(),
		issuerClient: issuer.Client(),
		dnsClient:    dns.Client(),
	}
}

// MainClient returns client for the main cluster containing certificate and source resources.
func (a *ClusterAccess) MainClient() client.Client {
	return a.mainClient
}

// IssuerClient returns client for the cluster containing provided issuers.
func (a *ClusterAccess) IssuerClient() client.Client {
	return a.issuerClient
}

// DNSClient returns client for the cluster used for DNSEntries or DNSRecords.
func (a *ClusterAccess) DNSClient() client.Client {
	return a.dnsClient
}

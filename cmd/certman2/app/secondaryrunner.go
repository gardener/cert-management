package app

import (
	"context"
	"fmt"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/cert-management/pkg/certman2/apis/config"
	"github.com/gardener/cert-management/pkg/certman2/controller/issuer"
)

// secondaryRunner implements the Controller-Runtime's Runnable interface and is used to add further controllers
// while the manager already has been started.
type secondaryRunner struct {
	mgr                   manager.Manager
	cfg                   *config.CertManagerConfiguration
	waitForLeaderElection <-chan struct{}
}

func (r *secondaryRunner) Start(ctx context.Context) error {
	log := r.mgr.GetLogger()

	log.Info("waiting for leader election in primary manager")
	<-r.waitForLeaderElection
	log.Info("leader elected in primary manager")

	waitForSyncCtx, waitForSyncCancel := context.WithTimeout(ctx, 5*time.Second)
	defer waitForSyncCancel()

	log.Info("Waiting for cache to be synced")
	if !r.mgr.GetCache().WaitForCacheSync(waitForSyncCtx) {
		return fmt.Errorf("failed waiting for cache to be synced")
	}

	log.Info("Adding controllers to manager")
	if err := (&issuer.Reconciler{
		Config: *r.cfg,
	}).AddToManager(r.mgr); err != nil {
		return fmt.Errorf("failed adding Issuer controller: %w", err)
	}

	return nil
}

// awaitLeaderElection is used to sync secondary manager with leader election of primary manager.
type awaitLeaderElection struct {
	waitForLeaderElection chan<- struct{}
}

var _ manager.Runnable = &awaitLeaderElection{}
var _ manager.LeaderElectionRunnable = &awaitLeaderElection{}

func (e *awaitLeaderElection) Start(_ context.Context) error {
	e.waitForLeaderElection <- struct{}{}
	close(e.waitForLeaderElection)
	return nil
}

func (e *awaitLeaderElection) NeedLeaderElection() bool {
	return true
}

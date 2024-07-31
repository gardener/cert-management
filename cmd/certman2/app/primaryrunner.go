package app

import (
	"context"
	"fmt"
	"time"

	"github.com/gardener/cert-management/pkg/certman2/apis/config"
	"github.com/gardener/cert-management/pkg/certman2/controller/certificate"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// primaryRunner implements the Controller-Runtime's Runnable interface and is used to add further controllers
// while the manager already has been started.
type primaryRunner struct {
	mgr manager.Manager
	cfg *config.CertManagerConfiguration
}

func (r *primaryRunner) Start(ctx context.Context) error {
	log := r.mgr.GetLogger()

	waitForSyncCtx, waitForSyncCancel := context.WithTimeout(ctx, 5*time.Second)
	defer waitForSyncCancel()

	log.Info("Waiting for cache to be synced")
	if !r.mgr.GetCache().WaitForCacheSync(waitForSyncCtx) {
		return fmt.Errorf("failed waiting for cache to be synced")
	}

	log.Info("Adding controllers to manager")
	if err := (&certificate.Reconciler{
		Config: *r.cfg,
	}).AddToManager(r.mgr); err != nil {
		return fmt.Errorf("failed adding Certificate controller: %w", err)
	}

	return nil
}

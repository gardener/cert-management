/*
 * SPDX-FileCopyrightText: Contributors to the Gardener project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package functional

import (
	"sync"

	"github.com/gardener/cert-management/test/functional/config"
)

var _config *config.Config
var lock sync.Mutex

func addIssuerTests(testFactory issuerTestFactory) {
	lock.Lock()
	defer lock.Unlock()

	if _config == nil {
		_config = config.InitConfig()
	}

	for _, issuer := range _config.Issuers {
		testFactory(_config, issuer)
	}
}

// getConfig returns the shared, lazily-initialised functional test configuration.
// It is used by issuer-independent tests (e.g. the CA injector) that only need the
// test utilities and not the per-issuer fan-out of addIssuerTests.
func getConfig() *config.Config {
	lock.Lock()
	defer lock.Unlock()

	if _config == nil {
		_config = config.InitConfig()
	}
	return _config
}

type issuerTestFactory func(config *config.Config, issuer *config.IssuerConfig)

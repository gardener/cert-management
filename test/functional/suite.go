/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package functional

import (
	"github.com/gardener/cert-management/test/functional/config"
	"sync"
)

var _config *config.Config
var lock sync.Mutex

func addIssuerTests(testFactory IssuerTestFactory) {
	lock.Lock()
	defer lock.Unlock()

	if _config == nil {
		_config = config.InitConfig()
	}

	for _, issuer := range _config.Issuers {
		testFactory(_config, issuer)
	}
}

type IssuerTestFactory func(config *config.Config, issuer *config.IssuerConfig)

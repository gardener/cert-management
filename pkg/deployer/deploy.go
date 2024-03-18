/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package deployer

import (
	"context"

	"github.com/gardener/gardener/pkg/component"
)

type deployer struct {
	values Values
}

var _ component.DeployWaiter = (*deployer)(nil)

// New returns a new 'cert-management' deployer instance.
func New(values Values) component.DeployWaiter {
	return &deployer{
		values: values,
	}
}

func (d deployer) Deploy(ctx context.Context) error {
	//TODO implement me
	panic("implement me")
}

func (d deployer) Destroy(ctx context.Context) error {
	//TODO implement me
	panic("implement me")
}

func (d deployer) Wait(ctx context.Context) error {
	//TODO implement me
	panic("implement me")
}

func (d deployer) WaitCleanup(ctx context.Context) error {
	//TODO implement me
	panic("implement me")
}

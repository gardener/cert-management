/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package functional

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {
})

func TestFunctionalTests(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Functional Test Suite for Cert Controller Manager")
}

var _ = AfterSuite(func() {
})

/*
 * SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package cainjector

import (
	cmlcontroller "github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	ctrl "github.com/gardener/cert-management/pkg/controller"
)

var _ = Describe("controller registration", func() {
	controllerNames := []string{
		"cainjector-validatingwebhook",
		"cainjector-mutatingwebhook",
		"cainjector-crd",
		"cainjector-apiservice",
	}

	definitions := cmlcontroller.DefaultDefinitions()

	It("registers all four CA injector controllers", func() {
		for _, name := range controllerNames {
			Expect(definitions.Get(name)).NotTo(BeNil(), "controller %q must be registered", name)
		}
	})

	It("registers them as opt-in (ActivateExplicitly)", func() {
		for _, name := range controllerNames {
			def := definitions.Get(name)
			Expect(def).NotTo(BeNil())
			Expect(def.ActivateExplicitly()).To(BeTrue(), "controller %q must be opt-in", name)
		}
	})

	It("groups them under the dedicated CA injector group, excluded from the default activation set", func() {
		grp := definitions.Groups().Get(ctrl.ControllerGroupCAInjector)
		Expect(grp).NotTo(BeNil())
		for _, name := range controllerNames {
			Expect(grp.Members().Contains(name)).To(BeTrue(), "controller %q must be a member of group %q", name, ctrl.ControllerGroupCAInjector)
		}
		// Opt-in controllers are not part of the set activated when --controllers is empty / "all".
		nonExplicit := definitions.Groups().AllNonExplicitMembers()
		for _, name := range controllerNames {
			Expect(nonExplicit.Contains(name)).To(BeFalse(), "controller %q must not be activated by default", name)
		}
	})
})

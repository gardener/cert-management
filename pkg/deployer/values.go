/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package deployer

// Values contains configuration options for the deployer.
type Values struct {
	Name      string
	Namespace string
	PodLabels map[string]string
	Image     string
	Config    Configuration
}

// Configuration contains configuration options for 'cert-management'.
type Configuration struct {
	HttpServerPort      int32
	CACertificateBundle *string
}

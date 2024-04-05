/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package deployer

// Values contains configuration options for the deployer.
type Values struct {
	Name                  string            `json:"name"`
	Namespace             string            `json:"namespace"`
	PodLabels             map[string]string `json:"podLabels"`
	Image                 string            `json:"image"`
	Config                Configuration     `json:"config"`
	ManagedResourceConfig ManagedResourceConfig
}

// ManagedResourceConfig contains configuration for the managed resource creation.
type ManagedResourceConfig struct {
	Namespace      string
	Labels         map[string]string
	InjectedLabels map[string]string
	Class          string
}

// Configuration contains configuration options for 'cert-management'.
type Configuration struct {
	HttpServerPort      int32   `json:"httpServerPort"`
	CACertificateBundle *string `json:"caCertificateBundle,omitempty"`
}

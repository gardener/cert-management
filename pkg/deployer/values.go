/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package deployer

// Values contains configuration options for the deployer.
type Values struct {
	Name      string            `json:"name" yaml:"name"`
	Namespace string            `json:"namespace" yaml:"namespace"`
	PodLabels map[string]string `json:"podLabels" yaml:"podLabels"`
	Image     string            `json:"image" yaml:"image"`
	Config    Configuration     `json:"config" yaml:"config"`
}

// Configuration contains configuration options for 'cert-management'.
type Configuration struct {
	HttpServerPort      int32   `json:"httpServerPort" yaml:"httpServerPort"`
	CACertificateBundle *string `json:"caCertificateBundle,omitempty" yaml:"caCertificateBundle,omitempty"`
}

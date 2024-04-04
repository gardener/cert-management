/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package deployer

// Values contains configuration options for the deployer.
type Values struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	PodLabels map[string]string `json:"podLabels"`
	Image     string            `json:"image"`
	Config    Configuration     `json:"config"`
}

// Configuration contains configuration options for 'cert-management'.
type Configuration struct {
	HttpServerPort      int32   `json:"httpServerPort"`
	CACertificateBundle *string `json:"caCertificateBundle,omitempty"`
}

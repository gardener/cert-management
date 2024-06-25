/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package config

import (
	"fmt"
	"os"
	"text/template"

	"k8s.io/apimachinery/pkg/util/yaml"
)

var (
	kubeconfig     string
	configFilename = "functest-config.yaml"
	namespace      = "default"
	dnsKubeconfig  string
	dnsDomain      string
)

func init() {
	kubeconfig = os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		panic("KUBECONFIG not set")
	}

	dnsKubeconfig = os.Getenv("DNS_KUBECONFIG")
	if dnsKubeconfig == "" {
		panic("DNS_KUBECONFIG not set")
	}

	dnsDomain = os.Getenv("DNS_DOMAIN")
	if dnsDomain == "" {
		panic("DNS_DOMAIN not set")
	}

	value := os.Getenv("NAMESPACE")
	if value != "" {
		namespace = value
	}

	value = os.Getenv("FUNCTEST_CONFIG")
	if value != "" {
		configFilename = value
	}
}

func PrintConfigEnv() {
	fmt.Printf("FUNCTEST_CONFIG=%s\n", configFilename)
	fmt.Printf("KUBECONFIG=%s\n", kubeconfig)
	fmt.Printf("DNS_KUBECONFIG=%s\n", dnsKubeconfig)
	fmt.Printf("DNS_DOMAIN=%s\n", dnsDomain)
	fmt.Printf("NAMESPACE=%s\n", namespace)
}

type IssuerConfig struct {
	Name                       string                  `json:"name"`
	Type                       string                  `json:"type"`
	AutoRegistration           bool                    `json:"autoRegistration"`
	Server                     string                  `json:"server,omitempty"`
	PrecheckNameservers        []string                `json:"precheckNameservers,omitempty"`
	Email                      string                  `json:"email,omitempty"`
	ExternalAccountBinding     *ExternalAccountBinding `json:"externalAccountBinding,omitempty"`
	SkipDNSChallengeValidation bool                    `json:"skipDNSChallengeValidation,omitempty"`
	PrivateKey                 string                  `json:"privateKey,omitempty"`
	SkipRevokeWithRenewal      bool                    `json:"skipRevokeWithRenewal,omitempty"`

	Namespace string
	Domain    string
}

type ExternalAccountBinding struct {
	KeyID   string `json:"keyID"`
	HmacKey string `json:"hmacKey"`
}

type Config struct {
	Issuers []*IssuerConfig `json:"issuers"`

	KubeConfig    string
	Namespace     string
	DNSKubeConfig string
	DNSDomain     string
	Utils         *TestUtils
}

func InitConfig() *Config {
	cfg, err := LoadConfig(configFilename)
	if err != nil {
		panic(err)
	}
	return cfg
}

func LoadConfig(filename string) (*Config, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	decoder := yaml.NewYAMLOrJSONDecoder(f, 2000)
	config := &Config{}
	err = decoder.Decode(config)
	if err != nil {
		return nil, fmt.Errorf("Parsing config file %s failed: %w", filename, err)
	}

	err = config.postProcess()
	if err != nil {
		return nil, fmt.Errorf("Post processing config file %s failed: %w", filename, err)
	}

	config.Utils = CreateDefaultTestUtils()

	return config, nil
}

func (c *Config) postProcess() error {
	c.Namespace = namespace
	c.KubeConfig = kubeconfig
	c.DNSKubeConfig = dnsKubeconfig
	c.DNSDomain = dnsDomain

	names := map[string]*IssuerConfig{}
	for _, issuer := range c.Issuers {
		if issuer.Name == "" {
			return fmt.Errorf("Invalid issuer configuration: missing name")
		}
		if names[issuer.Name] != nil {
			return fmt.Errorf("Duplicate issuer %s", issuer.Name)
		}
		names[issuer.Name] = issuer
		issuer.Namespace = c.Namespace
		issuer.Domain = c.DNSDomain
		if issuer.Type == "acme" {
			if issuer.Server == "" {
				return fmt.Errorf("Missing ACME server for %s", issuer.Name)
			}
			if issuer.Email == "" {
				return fmt.Errorf("Missing ACME email for %s", issuer.Name)
			}
			if !issuer.AutoRegistration && issuer.PrivateKey == "" {
				return fmt.Errorf("Functional test only supports autoRegistration or privateKey for ACME, see issuer %s", issuer.Name)
			}
		}
	}
	return nil
}

func (p *IssuerConfig) CreateTempManifest(name, templateContent string) (string, error) {
	tmpl, err := template.New(name).Parse(templateContent)

	f, err := os.CreateTemp("", fmt.Sprintf("%s-*.yaml", p.Name))
	if err != nil {
		return "", err
	}
	defer f.Close()

	return f.Name(), tmpl.Execute(f, p)
}

func (p *IssuerConfig) DeleteTempManifest(filename string) {
	if filename != "" {
		_ = os.Remove(filename)
	}
}

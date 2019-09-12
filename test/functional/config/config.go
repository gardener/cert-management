/*
 * Copyright 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 *
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
	Name             string `json:"name"`
	Type             string `json:"type"`
	AutoRegistration bool   `json:"autoRegistration"`
	Server           string `json:"server,omitempty"`
	Email            string `json:"email,omitempty"`

	Namespace           string
	TmpManifestFilename string
	Domain              string
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
		return nil, fmt.Errorf("Parsing config file %s failed with %s", filename, err)
	}

	err = config.postProcess()
	if err != nil {
		return nil, fmt.Errorf("Post processing config file %s failed with %s", filename, err)
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
			if !issuer.AutoRegistration {
				return fmt.Errorf("Functional test only supports autoRegistration for ACME, see issuer %s", issuer.Name)
			}
		}
	}
	return nil
}

func (p *IssuerConfig) CreateTempManifest(basePath string, manifestTemplate *template.Template) error {
	p.TmpManifestFilename = ""
	filename := fmt.Sprintf("%s/tmp-%s.yaml", basePath, p.Name)
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	p.TmpManifestFilename = filename

	return manifestTemplate.Execute(f, p)
}

func (p *IssuerConfig) DeleteTempManifest() {
	if p.TmpManifestFilename != "" {
		_ = os.Remove(p.TmpManifestFilename)
	}
}

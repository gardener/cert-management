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

package legobridge

import (
	"fmt"

	"github.com/go-acme/lego/challenge"
	"github.com/go-acme/lego/challenge/dns01"

	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	dnsapi "github.com/gardener/external-dns-management/pkg/apis/dns/v1alpha1"
	"github.com/gardener/external-dns-management/pkg/dns"
)

func newDNSControllerProvider(logger logger.LogContext, cluster resources.Cluster, settings DNSControllerSettings,
	certificateName resources.ObjectName) (challenge.Provider, error) {
	itf, err := cluster.Resources().GetByExample(&dnsapi.DNSEntry{})
	if err != nil {
		return nil, fmt.Errorf("cannot get DNSEntry resources: %s", err.Error())
	}
	return &dnsControllerProvider{logger: logger, settings: settings, entryResources: itf,
		certificateName: certificateName}, nil
}

type dnsControllerProvider struct {
	logger          logger.LogContext
	settings        DNSControllerSettings
	entryResources  resources.Interface
	certificateName resources.ObjectName
}

var _ challenge.Provider = &dnsControllerProvider{}

func (p *dnsControllerProvider) Present(domain, token, keyAuth string) error {
	fqdn, value := dns01.GetRecord(domain, keyAuth)
	entry := &dnsapi.DNSEntry{}
	entry.Name = domain
	entry.Namespace = p.settings.Namespace
	entry.Spec.DNSName = dns.NormalizeHostname(fqdn)
	entry.Spec.OwnerId = p.settings.OwnerId
	entry.Spec.Text = []string{value}

	logger.Infof("presenting DNSEntry %s/%s for certificate resource %s", entry.Namespace, entry.Name, p.certificateName)

	_, err := p.entryResources.CreateOrUpdate(entry)
	if err != nil {
		return fmt.Errorf("creating DNSEntry %s/%s failed with %s", entry.Namespace, entry.Name, err.Error())
	}
	return nil
}

func (p *dnsControllerProvider) CleanUp(domain, token, keyAuth string) error {
	entry := &dnsapi.DNSEntry{}
	entry.Name = domain
	entry.Namespace = p.settings.Namespace

	logger.Infof("cleanup DNSEntry %s/%s for request %s", entry.Namespace, entry.Name, p.certificateName)

	err := p.entryResources.Delete(entry)
	if err != nil {
		return fmt.Errorf("deleting DNSEntry %s/%s failed with %s", entry.Namespace, entry.Name, err.Error())
	}
	return nil
}

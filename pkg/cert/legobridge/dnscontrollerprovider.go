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
	"github.com/gardener/cert-management/pkg/cert/metrics"
	"github.com/gardener/cert-management/pkg/cert/source"
	"k8s.io/apimachinery/pkg/util/wait"
	"sync/atomic"
	"time"

	"github.com/go-acme/lego/challenge"
	"github.com/go-acme/lego/challenge/dns01"

	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	dnsapi "github.com/gardener/external-dns-management/pkg/apis/dns/v1alpha1"
	"github.com/gardener/external-dns-management/pkg/dns"
)

// ProviderWithCount is an extended Provider interface.
type ProviderWithCount interface {
	challenge.Provider
	GetChallengesCount() int
}

func newDNSControllerProvider(logger logger.LogContext, cluster resources.Cluster, settings DNSControllerSettings,
	certificateName resources.ObjectName, targetClass, issuerName string) (ProviderWithCount, error) {
	itf, err := cluster.Resources().GetByExample(&dnsapi.DNSEntry{})
	if err != nil {
		return nil, fmt.Errorf("cannot get DNSEntry resources: %s", err.Error())
	}
	return &dnsControllerProvider{logger: logger, settings: settings, entryResources: itf,
		certificateName: certificateName, targetClass: targetClass, issuerName: issuerName,
		ttl:         int64(0.501 * dns01.DefaultPropagationTimeout.Seconds()),
		initialWait: true,
		presenting:  map[string][]string{}}, nil
}

type dnsControllerProvider struct {
	logger          logger.LogContext
	settings        DNSControllerSettings
	entryResources  resources.Interface
	certificateName resources.ObjectName
	targetClass     string
	issuerName      string
	count           int32
	ttl             int64
	presenting      map[string][]string
	multiValues     bool
	initialWait     bool
}

var _ challenge.Provider = &dnsControllerProvider{}
var _ challenge.ProviderTimeout = &dnsControllerProvider{}

var backoff = wait.Backoff{
	Steps:    4,
	Duration: 500 * time.Millisecond,
	Factor:   2.0,
	Jitter:   0.1,
	Cap:      2500 * time.Millisecond,
}

type updateError struct {
	msg string
}

func (e *updateError) Error() string {
	return e.msg
}

func retryOnUpdateError(fn func() error) error {
	var lastUpdateErr error
	err := wait.ExponentialBackoff(backoff, func() (bool, error) {
		err := fn()
		_, isUpdateErr := err.(*updateError)
		switch {
		case err == nil:
			return true, nil
		case isUpdateErr:
			lastUpdateErr = err
			return false, nil
		default:
			return false, err
		}
	})
	if err == wait.ErrWaitTimeout {
		err = lastUpdateErr
	}
	return err
}

func (p *dnsControllerProvider) Present(domain, token, keyAuth string) error {
	metrics.AddActiveACMEDNSChallenge(p.issuerName)
	atomic.AddInt32(&p.count, 1)
	fqdn, value := dns01.GetRecord(domain, keyAuth)

	values := p.addPresentingDomainValue(domain, value)

	setSpec := func(e *dnsapi.DNSEntry) {
		e.Spec.DNSName = dns.NormalizeHostname(fqdn)
		e.Spec.OwnerId = p.settings.OwnerID
		e.Spec.TTL = &p.ttl
		e.Spec.Text = values
		resources.SetAnnotation(e, source.AnnotClass, p.targetClass)
	}

	entry := p.prepareEntry(domain)

	if len(values) == 1 {
		setSpec(entry)
		p.logger.Infof("presenting DNSEntry %s/%s for certificate resource %ss", entry.Namespace, entry.Name, p.certificateName)
		_, err := p.entryResources.Create(entry)
		if err != nil {
			return fmt.Errorf("creating DNSEntry %s/%s failed with %s", entry.Namespace, entry.Name, err.Error())
		}
		return nil
	}

	p.multiValues = true
	err := retryOnUpdateError(func() error {
		obj, err := p.entryResources.Get_(entry)
		if err != nil {
			return fmt.Errorf("getting DNSEntry %s/%s failed with %s", entry.Namespace, entry.Name, err.Error())
		}
		entry = obj.Data().(*dnsapi.DNSEntry)
		setSpec(entry)
		p.logger.Infof("presenting DNSEntry %s/%s for certificate resource %s with %d values", entry.Namespace, entry.Name, p.certificateName, len(values))
		_, err = p.entryResources.Update(entry)
		if err != nil {
			return &updateError{msg: fmt.Sprintf("updating DNSEntry %s/%s failed with %s", entry.Namespace, entry.Name, err.Error())}
		}
		return nil
	})
	return err
}

func (p *dnsControllerProvider) addPresentingDomainValue(domain, value string) []string {
	values := append(p.presenting[domain], value)
	p.presenting[domain] = values
	return values
}

func (p *dnsControllerProvider) removePresentingDomain(domain string) bool {
	if _, found := p.presenting[domain]; !found {
		return false
	}
	delete(p.presenting, domain)
	return true
}

func (p *dnsControllerProvider) CleanUp(domain, token, keyAuth string) error {
	metrics.RemoveActiveACMEDNSChallenge(p.issuerName)

	if !p.removePresentingDomain(domain) {
		return nil
	}

	entry := p.prepareEntry(domain)
	p.logger.Infof("cleanup DNSEntry %s/%s for request %s", entry.Namespace, entry.Name, p.certificateName)
	err := p.entryResources.Delete(entry)
	if err != nil {
		return fmt.Errorf("deleting DNSEntry %s/%s failed with %s", entry.Namespace, entry.Name, err.Error())
	}
	return nil
}

func (p *dnsControllerProvider) GetChallengesCount() int {
	return int(atomic.LoadInt32(&p.count))
}

func (p *dnsControllerProvider) prepareEntry(domain string) *dnsapi.DNSEntry {
	entry := &dnsapi.DNSEntry{}
	entry.Name = "cert--" + domain
	entry.Namespace = p.settings.Namespace
	return entry
}

func (p *dnsControllerProvider) dnsEntryPending(domain string, valuesCount int) bool {
	entry := p.prepareEntry(domain)
	obj, err := p.entryResources.Get_(entry)
	if err != nil {
		return false // no more waiting
	}
	entry = obj.Data().(*dnsapi.DNSEntry)
	return entry.Status.State == "Pending" || entry.Status.State == "Ready" && len(entry.Status.Targets) != valuesCount
}

func (p *dnsControllerProvider) Timeout() (timeout, interval time.Duration) {
	if p.initialWait {
		p.initialWait = false
		// The Timeout function is called several times after all domains are "presented".
		// On the first call it is checked that no DNS entries are pending anymore.
		// Depending on number of domain names and possible parallel other work,
		// the dns-controller-manager may need several change batches
		// until all entries are ready
		rounds := 10
		waitTime := dns01.DefaultPropagationTimeout / time.Duration(rounds)
	outer:
		for i := 0; i < rounds; i++ {
			ready := true
			for domain, values := range p.presenting {
				if p.dnsEntryPending(domain, len(values)) {
					ready = false
					break
				}
			}
			if ready {
				break outer
			}
			p.logger.Infof("Waiting %d seconds for DNS entries getting ready...", int(waitTime.Seconds()))
			time.Sleep(waitTime)
		}

		// wait some additional time for DNS record propagation
		propagationWaitTime := 10
		if p.multiValues {
			// If there are multiple DNSChallenges for one domain the DNS record may be propagated with incomplete values
			// Therefore await end of live of the first, incomplete DNS record
			propagationWaitTime += int(p.ttl)
		}
		p.logger.Infof("Waiting %d seconds for initial DNS record propagation...", int(propagationWaitTime))
		time.Sleep(time.Duration(propagationWaitTime) * time.Second)
	}
	return dns01.DefaultPropagationTimeout, dns01.DefaultPollingInterval
}

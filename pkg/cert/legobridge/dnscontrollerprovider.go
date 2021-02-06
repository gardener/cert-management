/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package legobridge

import (
	"fmt"
	"sync/atomic"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/gardener/cert-management/pkg/cert/metrics"
	"github.com/gardener/cert-management/pkg/cert/source"
	"github.com/gardener/cert-management/pkg/cert/utils"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"

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

var index uint32

func newDNSControllerProvider(settings DNSControllerSettings,
	certificateName resources.ObjectName, targetClass, issuerName string) (ProviderWithCount, error) {
	itf, err := settings.Cluster.Resources().GetByExample(&dnsapi.DNSEntry{})
	if err != nil {
		return nil, fmt.Errorf("cannot get DNSEntry resources: %s", err.Error())
	}
	n := atomic.AddUint32(&index, 1)
	return &dnsControllerProvider{
		logger:          logger.NewContext("DNSChallengeProvider", fmt.Sprintf("dns-challenge-provider: %s-%d", certificateName, n)),
		settings:        settings,
		entryResources:  itf,
		certificateName: certificateName,
		targetClass:     targetClass,
		issuerName:      issuerName,
		ttl:             int64(settings.PropagationTimeout.Seconds()),
		initialWait:     true,
		presenting:      map[string][]string{}}, nil
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
		if p.targetClass != "" {
			resources.SetAnnotation(e, source.AnnotDNSClass, p.targetClass)
		}
	}

	entry := p.prepareEntry(domain)

	if len(values) == 1 {
		setSpec(entry)
		p.logger.Infof("presenting DNSEntry %s/%s for certificate resource %s", entry.Namespace, entry.Name, p.certificateName)
		if p.existsBlockingEntry(entry) {
			p.removePresentingDomain(domain)
			return fmt.Errorf("already existing DNSEntry %s/%s for certificate resource %s", entry.Namespace, entry.Name, p.certificateName)
		}
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

func (p *dnsControllerProvider) existsBlockingEntry(entry *dnsapi.DNSEntry) bool {
	objectName := resources.NewObjectName(entry.Namespace, entry.Name)
	obj, err := p.entryResources.Get_(objectName)
	if err != nil {
		return false
	}

	keep := obj.GetCreationTimestamp().Add(3 * time.Minute).After(time.Now())
	if !keep {
		// delete outdated or foreign DNSEntry
		_ = p.entryResources.DeleteByName(objectName)
	}
	return keep
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

func (p *dnsControllerProvider) checkDNSEntryNotPending(domain string, values []string) bool {
	entry := p.prepareEntry(domain)
	obj, err := p.entryResources.Get_(entry)
	if err != nil {
		return true // no more waiting
	}
	entry = obj.Data().(*dnsapi.DNSEntry)
	return !(entry.Status.State == "Pending" || entry.Status.State == "Ready" && len(entry.Status.Targets) != len(values))
}

func (p *dnsControllerProvider) Timeout() (timeout, interval time.Duration) {
	waitTimeout := p.settings.PropagationTimeout
	if p.initialWait {
		p.initialWait = false
		// The Timeout function is called several times after all domains are "presented".
		// On the first call it is checked that no DNS entries are pending anymore.
		// Depending on number of domain names and possible parallel other work,
		// the dns-controller-manager may need several change batches
		// until all entries are ready

		prepareWaitTimeout := waitTimeout + 5*time.Second*time.Duration(len(p.presenting))
		p.waitFor("DNS entry getting ready", p.checkDNSEntryNotPending, prepareWaitTimeout)

		if p.waitFor("DNS record propagation", p.isDNSTxtRecordReady, waitTimeout) {
			// wait some additional seconds to enlarge probability of record propagation to DNS server use by ACME server
			additionalWaitTime := p.settings.AdditionalWait
			p.logger.Infof("Waiting additional %d seconds...", int(additionalWaitTime.Seconds()))
			time.Sleep(additionalWaitTime)
		}
	}
	return waitTimeout / 2, dns01.DefaultPollingInterval
}

func (p *dnsControllerProvider) waitFor(msg string, isReady func(domain string, values []string) bool, timeout time.Duration) bool {
	waitTime := 5 * time.Second
	endTime := time.Now().Add(timeout)
	pendingDomain := ""
	for time.Now().Before(endTime) {
		ready := true
		for domain, values := range p.presenting {
			if !isReady(domain, values) {
				pendingDomain = domain
				ready = false
				break
			}
		}
		if ready {
			return true
		}
		p.logger.Infof("Waiting %d seconds for %s [%s]...", int(waitTime.Seconds()), msg, pendingDomain)
		time.Sleep(waitTime)
	}
	return false
}

func (p *dnsControllerProvider) isDNSTxtRecordReady(domain string, values []string) bool {
	fqdn := fmt.Sprintf("_acme-challenge.%s.", domain)
	found, _ := utils.CheckDNSPropagation(p.settings.PrecheckNameservers, fqdn, values...)
	return found
}

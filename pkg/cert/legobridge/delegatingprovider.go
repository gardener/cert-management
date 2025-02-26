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

	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/gardener/cert-management/pkg/cert/utils"
	"github.com/gardener/cert-management/pkg/shared"
	"github.com/gardener/cert-management/pkg/shared/metrics"
)

// ProviderWithCount is an extended Provider interface.
type ProviderWithCount interface {
	challenge.Provider
	GetChallengesCount() int
	// GetPendingTXTRecordError returns error with details if a TXT record for DNS challenge is not ready.
	GetPendingTXTRecordError() error
}

type internalProvider interface {
	present(log logger.LogContext, domain, fqdn string, values []string) (error, bool)
	cleanup(log logger.LogContext, domain string) error

	failedDNSResourceReadyMessage(final bool) string
	checkDNSResourceReady(domain string, values []string) bool
}

var serial uint32

func newDelegatingProvider(
	settings DNSControllerSettings,
	certificateName resources.ObjectName,
	targetClass string,
	issuerKey shared.IssuerKeyItf,
) (ProviderWithCount, error) {
	n := atomic.AddUint32(&serial, 1)
	var internalPrvdr internalProvider
	var err error
	if settings.DNSRecordSettings == nil {
		internalPrvdr, err = newDNSControllerProvider(settings, targetClass)
	} else {
		internalPrvdr, err = newDNSRecordProvider(settings)
	}
	return &delegatingProvider{
		logger:           logger.NewContext("DNSChallengeProvider", fmt.Sprintf("dns-challenge-provider: %s-%d", certificateName, n)),
		settings:         settings,
		issuerKey:        issuerKey,
		initialWait:      true,
		presenting:       map[string][]string{},
		internalProvider: internalPrvdr,
	}, err
}

type delegatingProvider struct {
	logger      logger.LogContext
	settings    DNSControllerSettings
	issuerKey   shared.IssuerKeyItf
	count       int32
	presenting  map[string][]string
	initialWait bool

	failedPendingDomain string
	failedPendingCheck  string
	internalProvider    internalProvider
}

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
	if wait.Interrupted(err) {
		err = lastUpdateErr
	}
	return err
}

func (p *delegatingProvider) Present(domain, _, keyAuth string) error {
	metrics.AddActiveACMEDNSChallenge(p.issuerKey)
	atomic.AddInt32(&p.count, 1)
	info := dns01.GetChallengeInfo(domain, keyAuth)
	value := info.Value
	fqdn := info.FQDN

	if p.settings.FollowCNAME {
		var err error
		orgfqdn := fqdn
		fqdn, err = utils.FollowCNAMEs(fqdn, p.settings.PrecheckNameservers)
		if err != nil {
			return fmt.Errorf("following CNAME for DNS01 challenge for %s failed: %w", orgfqdn, err)
		}
	}

	values := p.addPresentingDomainValue(domain, value)

	err, remove := p.internalProvider.present(p.logger, domain, fqdn, values)
	if remove {
		p.removePresentingDomain(domain)
	}
	return err
}

func (p *delegatingProvider) addPresentingDomainValue(domain, value string) []string {
	values := append(p.presenting[domain], value)
	p.presenting[domain] = values
	return values
}

func (p *delegatingProvider) removePresentingDomain(domain string) bool {
	if _, found := p.presenting[domain]; !found {
		return false
	}
	delete(p.presenting, domain)
	return true
}

func (p *delegatingProvider) CleanUp(domain, _, _ string) error {
	metrics.RemoveActiveACMEDNSChallenge(p.issuerKey)

	if !p.removePresentingDomain(domain) {
		return nil
	}

	return p.internalProvider.cleanup(p.logger, domain)
}

func (p *delegatingProvider) GetChallengesCount() int {
	return int(atomic.LoadInt32(&p.count))
}

func (p *delegatingProvider) GetPendingTXTRecordError() error {
	if p.failedPendingDomain != "" {
		return fmt.Errorf("DNS TXT record '_acme-challenge.%s' is not visible on public (or precheck) name servers. Failed check: %s", p.failedPendingDomain, p.failedPendingCheck)
	}
	return nil
}

func (p *delegatingProvider) Timeout() (timeout, interval time.Duration) {
	waitTimeout := p.settings.PropagationTimeout
	if !p.initialWait {
		return 10 * time.Second, dns01.DefaultPollingInterval
	}

	p.initialWait = false
	// The Timeout function is called several times after all domains are "presented".
	// On the first call it is checked that no DNS entries are pending anymore.
	// Depending on number of domain names and possible parallel other work,
	// the dns-controller-manager may need several change batches
	// until all entries are ready

	prepareWaitTimeout := 30*time.Second + 5*time.Second*time.Duration(len(p.presenting))
	ok := p.waitFor(p.internalProvider.failedDNSResourceReadyMessage, p.internalProvider.checkDNSResourceReady, prepareWaitTimeout)
	if ok {
		ok = p.waitFor(func(bool) string { return "DNS record propagation" }, p.isDNSTxtRecordReady, waitTimeout)
	}
	if ok {
		// wait some additional seconds to enlarge probability of record propagation to DNS server use by ACME server
		additionalWaitTime := p.settings.AdditionalWait
		p.logger.Infof("Waiting additional %d seconds...", int(additionalWaitTime.Seconds()))
		time.Sleep(additionalWaitTime)
	}
	return waitTimeout / 2, dns01.DefaultPollingInterval
}

func (p *delegatingProvider) waitFor(msgfunc func(bool) string, isReady func(domain string, values []string) bool, timeout time.Duration) bool {
	p.failedPendingDomain = ""
	p.failedPendingCheck = ""

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
		p.logger.Infof("Waiting %d seconds for %s [%s]...", int(waitTime.Seconds()), msgfunc(false), pendingDomain)
		time.Sleep(waitTime)
	}

	p.failedPendingDomain = pendingDomain
	p.failedPendingCheck = msgfunc(true)
	return false
}

func (p *delegatingProvider) isDNSTxtRecordReady(domain string, values []string) bool {
	fqdn := fmt.Sprintf("_acme-challenge.%s.", domain)
	found, _ := utils.CheckDNSPropagation(p.settings.PrecheckNameservers, fqdn, values...)
	return found
}

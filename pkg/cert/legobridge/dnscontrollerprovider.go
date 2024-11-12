/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package legobridge

import (
	"errors"
	"fmt"
	"time"

	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	dnsapi "github.com/gardener/external-dns-management/pkg/apis/dns/v1alpha1"
	"github.com/gardener/external-dns-management/pkg/dns"
	"k8s.io/utils/ptr"

	"github.com/gardener/cert-management/pkg/cert/source"
)

func newDNSControllerProvider(settings DNSControllerSettings, targetClass string) (internalProvider, error) {
	itf, err := settings.Cluster.Resources().GetByExample(&dnsapi.DNSEntry{})
	if err != nil {
		return nil, fmt.Errorf("cannot get DNSEntry resources: %w", err)
	}
	return &dnsControllerProvider{
		settings:       settings,
		entryResources: itf,
		targetClass:    targetClass,
		entries:        map[string]*dnsapi.DNSEntry{},
	}, nil
}

type dnsControllerProvider struct {
	settings       DNSControllerSettings
	entryResources resources.Interface
	targetClass    string
	entries        map[string]*dnsapi.DNSEntry
}

var _ internalProvider = &dnsControllerProvider{}

func (p *dnsControllerProvider) present(log logger.LogContext, domain, fqdn string, values []string) (error, bool) {
	setSpec := func(e *dnsapi.DNSEntry) {
		e.Spec.DNSName = dns.NormalizeHostname(fqdn)
		e.Spec.OwnerId = p.settings.OwnerID
		e.Spec.TTL = ptr.To(int64(p.settings.PropagationTimeout.Seconds()))
		e.Spec.Text = values
		if p.targetClass != "" {
			resources.SetAnnotation(e, source.AnnotDNSClass, p.targetClass)
		}
		resources.SetAnnotation(e, source.AnnotACMEDNSChallenge, "true")
	}

	entry := p.prepareEntry(domain)

	if len(values) == 1 {
		setSpec(entry)
		log.Infof("presenting DNSEntry %s/%s", entry.Namespace, entry.Name)
		if p.existsBlockingEntry(entry) {
			return fmt.Errorf("already existing DNSEntry %s/%s", entry.Namespace, entry.Name), true
		}
		if _, err := p.entryResources.Create(entry); err != nil {
			return fmt.Errorf("creating DNSEntry %s/%s failed: %w", entry.Namespace, entry.Name, err), false
		}
		return nil, false
	}

	err := retryOnUpdateError(func() error {
		obj, err := p.entryResources.Get_(entry)
		if err != nil {
			return fmt.Errorf("getting DNSEntry %s/%s failed: %w", entry.Namespace, entry.Name, err)
		}
		entry = obj.Data().(*dnsapi.DNSEntry)
		setSpec(entry)
		log.Infof("presenting DNSEntry %s/%s with %d values", entry.Namespace, entry.Name, len(values))
		if _, err = p.entryResources.Update(entry); err != nil {
			return &updateError{msg: fmt.Sprintf("updating DNSEntry %s/%s failed: %s", entry.Namespace, entry.Name, err)}
		}
		return nil
	})
	return err, false
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

func (p *dnsControllerProvider) cleanup(log logger.LogContext, domain string) error {
	entry := p.prepareEntry(domain)
	log.Infof("cleanup DNSEntry %s/%s", entry.Namespace, entry.Name)
	if err := p.entryResources.Delete(entry); err != nil {
		return fmt.Errorf("deleting DNSEntry %s/%s failed: %w", entry.Namespace, entry.Name, err)
	}
	return nil
}

func (p *dnsControllerProvider) prepareEntry(domain string) *dnsapi.DNSEntry {
	entry := &dnsapi.DNSEntry{}
	entry.Name = "cert--" + domain
	entry.Namespace = p.settings.Namespace
	return entry
}

func (p *dnsControllerProvider) checkDNSResourceReady(domain string, _ []string) bool {
	entry := p.prepareEntry(domain)
	obj, err := p.entryResources.Get_(entry)
	if err != nil {
		return true // no more waiting
	}
	entry = obj.Data().(*dnsapi.DNSEntry)
	p.entries[domain] = entry
	return entry.Status.State == "Ready" && entry.Status.ObservedGeneration == entry.Generation
}

func (p *dnsControllerProvider) failedDNSResourceReadyMessage(final bool) string {
	if final {
		var errs []error
		for key, entry := range p.entries {
			switch {
			case entry.Status.State == "Ready":
				continue
			case entry.Status.State == "" && entry.Status.Provider == nil:
				errs = append(errs, fmt.Errorf("no provider found to apply DNS entry for %s", key))
			case entry.Status.Message != nil:
				errs = append(errs, fmt.Errorf("DNS entry for %s has state %s (%s)", key, entry.Status.State, *entry.Status.Message))
			default:
				errs = append(errs, fmt.Errorf("DNS entry for %s has state %s", key, entry.Status.State))
			}
		}
		if len(errs) > 0 {
			return "DNS entry getting ready: " + errors.Join(errs...).Error()
		}
	}
	return "DNS entry getting ready"
}

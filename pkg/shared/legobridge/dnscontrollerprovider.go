/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package legobridge

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	dnsapi "github.com/gardener/external-dns-management/pkg/apis/dns/v1alpha1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/cert-management/pkg/shared"
)

func newDNSControllerProvider(settings DNSControllerSettings, targetClass string) (internalProvider, error) {
	return &dnsControllerProvider{
		settings:    settings,
		targetClass: targetClass,
		entries:     map[string]*dnsapi.DNSEntry{},
	}, nil
}

type dnsControllerProvider struct {
	settings    DNSControllerSettings
	targetClass string
	entries     map[string]*dnsapi.DNSEntry
}

var _ internalProvider = &dnsControllerProvider{}

func (p *dnsControllerProvider) present(ctx context.Context, log LoggerInfof, domain, fqdn string, values []string) (error, bool) {
	setSpec := func(e *dnsapi.DNSEntry) {
		e.Spec.DNSName = strings.TrimSuffix(fqdn, ".")
		e.Spec.OwnerId = p.settings.OwnerID
		e.Spec.TTL = ptr.To(int64(p.settings.PropagationTimeout.Seconds()))
		e.Spec.Text = values
		if p.targetClass != "" {
			addAnnotation(e, shared.AnnotDNSClass, p.targetClass)
		}
		addAnnotation(e, shared.AnnotACMEDNSChallenge, "true")
	}

	entry := p.prepareEntry(domain)

	if len(values) == 1 {
		setSpec(entry)
		log.Infof("presenting DNSEntry %s/%s", entry.Namespace, entry.Name)
		if p.existsBlockingEntry(ctx, entry) {
			return fmt.Errorf("already existing DNSEntry %s/%s", entry.Namespace, entry.Name), true
		}
		if err := p.settings.Client.Create(ctx, entry); err != nil {
			return fmt.Errorf("creating DNSEntry %s/%s failed: %w", entry.Namespace, entry.Name, err), false
		}
		return nil, false
	}

	err := retryOnUpdateError(func() error {
		if err := p.settings.Client.Get(ctx, client.ObjectKeyFromObject(entry), entry); err != nil {
			return fmt.Errorf("getting DNSEntry %s/%s failed: %w", entry.Namespace, entry.Name, err)
		}
		setSpec(entry)
		log.Infof("presenting DNSEntry %s/%s with %d values", entry.Namespace, entry.Name, len(values))
		if err := p.settings.Client.Update(ctx, entry); err != nil {
			return &updateError{msg: fmt.Sprintf("updating DNSEntry %s/%s failed: %s", entry.Namespace, entry.Name, err)}
		}
		return nil
	})
	return err, false
}

func (p *dnsControllerProvider) existsBlockingEntry(ctx context.Context, entry *dnsapi.DNSEntry) bool {
	if err := p.settings.Client.Get(ctx, client.ObjectKeyFromObject(entry), entry); err != nil {
		return false
	}

	keep := entry.CreationTimestamp.Add(3 * time.Minute).After(time.Now())
	if !keep {
		// delete outdated or foreign DNSEntry
		_ = p.settings.Client.Delete(ctx, entry)
	}
	return keep
}

func (p *dnsControllerProvider) cleanup(ctx context.Context, log LoggerInfof, domain string) error {
	entry := p.prepareEntry(domain)
	log.Infof("cleanup DNSEntry %s/%s", entry.Namespace, entry.Name)
	if err := p.settings.Client.Delete(ctx, entry); err != nil {
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

func (p *dnsControllerProvider) checkDNSResourceReady(ctx context.Context, domain string, _ []string) bool {
	entry := p.prepareEntry(domain)
	if err := p.settings.Client.Get(ctx, client.ObjectKeyFromObject(entry), entry); err != nil {
		return true // no more waiting
	}
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

func addAnnotation(obj client.Object, key, value string) bool {
	if obj.GetAnnotations() == nil {
		obj.SetAnnotations(map[string]string{})
	}
	if obj.GetAnnotations()[key] == value {
		return false
	}
	obj.GetAnnotations()[key] = value
	return true
}

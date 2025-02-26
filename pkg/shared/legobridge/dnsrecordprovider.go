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
	"time"

	"github.com/gardener/external-dns-management/pkg/dns"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/cert-management/pkg/shared"
)

func newDNSRecordProvider(settings DNSControllerSettings) (internalProvider, error) {
	if settings.DNSRecordSettings == nil {
		return nil, fmt.Errorf("missing DNSRecord specific settings")
	}
	if settings.DNSRecordSettings.Type == "" {
		return nil, fmt.Errorf("missing DNSRecord provider type")
	}
	if settings.DNSRecordSettings.SecretRef.Name == "" {
		return nil, fmt.Errorf("missing DNSRecord secret reference")
	}
	return &dnsRecordProvider{
		settings: settings,
		entries:  map[string]*extensionsv1alpha.DNSRecord{},
	}, nil
}

type dnsRecordProvider struct {
	settings DNSControllerSettings
	entries  map[string]*extensionsv1alpha.DNSRecord
}

var _ internalProvider = &dnsRecordProvider{}

func (p *dnsRecordProvider) present(ctx context.Context, log LoggerInfof, domain, fqdn string, values []string) (error, bool) {
	setSpec := func(e *extensionsv1alpha.DNSRecord) {
		e.Spec.Name = dns.NormalizeHostname(fqdn)
		e.Spec.TTL = ptr.To(int64(p.settings.PropagationTimeout.Seconds()))
		e.Spec.RecordType = extensionsv1alpha.DNSRecordTypeTXT
		e.Spec.Type = p.settings.DNSRecordSettings.Type
		e.Spec.SecretRef = p.settings.DNSRecordSettings.SecretRef
		e.Spec.Values = values
		if p.settings.DNSRecordSettings.Class != "" {
			e.Spec.Class = ptr.To(extensionsv1alpha.ExtensionClass(p.settings.DNSRecordSettings.Class))
		}
		addAnnotation(e, shared.AnnotACMEDNSChallenge, "true")
	}

	entry := p.prepareEntry(domain)

	if len(values) == 1 {
		setSpec(entry)
		log.Infof("presenting DNSRecord %s/%s", entry.Namespace, entry.Name)
		if p.existsBlockingEntry(ctx, entry) {
			return fmt.Errorf("already existing DNSRecord %s/%s", entry.Namespace, entry.Name), true
		}
		if err := p.settings.Client.Create(ctx, entry); err != nil {
			return fmt.Errorf("creating DNSRecord %s/%s failed: %w", entry.Namespace, entry.Name, err), false
		}
		return nil, false
	}

	err := retryOnUpdateError(func() error {
		if err := p.settings.Client.Get(ctx, client.ObjectKeyFromObject(entry), entry); err != nil {
			return fmt.Errorf("getting DNSRecord %s/%s failed: %w", entry.Namespace, entry.Name, err)
		}
		setSpec(entry)
		log.Infof("presenting DNSRecord %s/%s with %d values", entry.Namespace, entry.Name, len(values))
		if err := p.settings.Client.Update(ctx, entry); err != nil {
			return &updateError{msg: fmt.Sprintf("updating DNSRecord %s/%s failed: %s", entry.Namespace, entry.Name, err)}
		}
		return nil
	})
	return err, false
}

func (p *dnsRecordProvider) existsBlockingEntry(ctx context.Context, entry *extensionsv1alpha.DNSRecord) bool {
	if err := p.settings.Client.Get(ctx, client.ObjectKeyFromObject(entry), entry); err != nil {
		return false
	}

	keep := entry.CreationTimestamp.Add(3 * time.Minute).After(time.Now())
	if !keep {
		// delete outdated or foreign DNSRecord
		_ = p.settings.Client.Delete(ctx, entry)
	}
	return keep
}

func (p *dnsRecordProvider) cleanup(ctx context.Context, log LoggerInfof, domain string) error {
	entry := p.prepareEntry(domain)
	log.Infof("cleanup DNSRecord %s/%s", entry.Namespace, entry.Name)
	if err := p.settings.Client.Get(ctx, client.ObjectKeyFromObject(entry), entry); err != nil {
		return fmt.Errorf("getting DNSRecord %s/%s failed: %w", entry.Namespace, entry.Name, err)
	}
	if addAnnotation(entry, v1beta1constants.ConfirmationDeletion, "true") {
		if err := p.settings.Client.Update(ctx, entry); err != nil {
			return fmt.Errorf("annotating DNSRecord %s/%s failed: %w", entry.Namespace, entry.Name, err)
		}
	}
	if err := p.settings.Client.Delete(ctx, entry); err != nil {
		return fmt.Errorf("deleting DNSRecord %s/%s failed: %w", entry.Namespace, entry.Name, err)
	}
	return nil
}

func (p *dnsRecordProvider) prepareEntry(domain string) *extensionsv1alpha.DNSRecord {
	entry := &extensionsv1alpha.DNSRecord{}
	entry.Name = "cert--" + domain
	entry.Namespace = p.settings.Namespace
	return entry
}

func (p *dnsRecordProvider) checkDNSResourceReady(ctx context.Context, domain string, _ []string) bool {
	entry := p.prepareEntry(domain)
	if err := p.settings.Client.Get(ctx, client.ObjectKeyFromObject(entry), entry); err != nil {
		return true // no more waiting
	}
	p.entries[domain] = entry
	return entry.Status.LastOperation != nil && entry.Status.LastOperation.State == gardencorev1beta1.LastOperationStateSucceeded &&
		entry.Generation == entry.Status.ObservedGeneration
}

func (p *dnsRecordProvider) failedDNSResourceReadyMessage(final bool) string {
	if final {
		var errs []error
		for key, entry := range p.entries {
			switch {
			case entry.Status.LastOperation == nil:
				errs = append(errs, fmt.Errorf("no provider found to apply DNSRecord for %s", key))
			case entry.Status.LastOperation.State == gardencorev1beta1.LastOperationStateSucceeded:
				continue
			case entry.Status.LastOperation.Description != "":
				errs = append(errs, fmt.Errorf("DNS entry for %s has state %s (%s)", key, entry.Status.LastOperation.State, entry.Status.LastOperation.Description))
			default:
				errs = append(errs, fmt.Errorf("DNS entry for %s has state %s", key, entry.Status.LastOperation.State))
			}
		}
		if len(errs) > 0 {
			return "DNSRecord getting ready: " + errors.Join(errs...).Error()
		}
	}
	return "DNSRecord getting ready"
}

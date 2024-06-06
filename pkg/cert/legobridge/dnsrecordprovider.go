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

	"github.com/gardener/cert-management/pkg/cert/source"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/utils/gardener"
	"k8s.io/utils/ptr"

	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/external-dns-management/pkg/dns"
	extensionsv1alpha "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
)

func newDNSRecordProvider(settings DNSControllerSettings) (internalProvider, error) {
	itf, err := settings.Cluster.Resources().GetByExample(&extensionsv1alpha.DNSRecord{})
	if err != nil {
		return nil, fmt.Errorf("cannot get DNSRecord resources: %w", err)
	}
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
		settings:           settings,
		dnsrecordResources: itf,
		entries:            map[string]*extensionsv1alpha.DNSRecord{},
	}, nil
}

type dnsRecordProvider struct {
	settings           DNSControllerSettings
	dnsrecordResources resources.Interface
	entries            map[string]*extensionsv1alpha.DNSRecord
}

var _ internalProvider = &dnsRecordProvider{}

func (p *dnsRecordProvider) present(log logger.LogContext, domain, fqdn string, values []string) (error, bool) {
	setSpec := func(e *extensionsv1alpha.DNSRecord) {
		e.Spec.Name = dns.NormalizeHostname(fqdn)
		e.Spec.TTL = ptr.To(int64(p.settings.PropagationTimeout.Seconds()))
		e.Spec.RecordType = extensionsv1alpha.DNSRecordTypeTXT
		e.Spec.Type = p.settings.DNSRecordSettings.Type
		e.Spec.SecretRef = p.settings.DNSRecordSettings.SecretRef
		e.Spec.Values = values
		resources.SetAnnotation(e, source.AnnotACMEDNSChallenge, "true")
	}

	entry := p.prepareEntry(domain)

	if len(values) == 1 {
		setSpec(entry)
		log.Infof("presenting DNSRecord %s/%s", entry.Namespace, entry.Name)
		if p.existsBlockingEntry(entry) {
			return fmt.Errorf("already existing DNSRecord %s/%s", entry.Namespace, entry.Name), true
		}
		if _, err := p.dnsrecordResources.Create(entry); err != nil {
			return fmt.Errorf("creating DNSRecord %s/%s failed: %w", entry.Namespace, entry.Name, err), false
		}
		return nil, false
	}

	err := retryOnUpdateError(func() error {
		obj, err := p.dnsrecordResources.Get_(entry)
		if err != nil {
			return fmt.Errorf("getting DNSRecord %s/%s failed: %w", entry.Namespace, entry.Name, err)
		}
		entry = obj.Data().(*extensionsv1alpha.DNSRecord)
		setSpec(entry)
		log.Infof("presenting DNSRecord %s/%s with %d values", entry.Namespace, entry.Name, len(values))
		if _, err = p.dnsrecordResources.Update(entry); err != nil {
			return &updateError{msg: fmt.Sprintf("updating DNSRecord %s/%s failed: %s", entry.Namespace, entry.Name, err)}
		}
		return nil
	})
	return err, false
}

func (p *dnsRecordProvider) existsBlockingEntry(entry *extensionsv1alpha.DNSRecord) bool {
	objectName := resources.NewObjectName(entry.Namespace, entry.Name)
	obj, err := p.dnsrecordResources.Get_(objectName)
	if err != nil {
		return false
	}

	keep := obj.GetCreationTimestamp().Add(3 * time.Minute).After(time.Now())
	if !keep {
		// delete outdated or foreign DNSRecord
		_ = p.dnsrecordResources.DeleteByName(objectName)
	}
	return keep
}

func (p *dnsRecordProvider) cleanup(log logger.LogContext, domain string) error {
	entry := p.prepareEntry(domain)
	log.Infof("cleanup DNSRecord %s/%s", entry.Namespace, entry.Name)
	if _, err := p.dnsrecordResources.GetInto1(entry); err != nil {
		return fmt.Errorf("getting DNSRecord %s/%s failed: %w", entry.Namespace, entry.Name, err)
	}
	if resources.SetAnnotation(entry, gardener.ConfirmationDeletion, "true") {
		if _, err := p.dnsrecordResources.Update(entry); err != nil {
			return fmt.Errorf("annotating DNSRecord %s/%s failed: %w", entry.Namespace, entry.Name, err)
		}
	}
	if err := p.dnsrecordResources.Delete(entry); err != nil {
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

func (p *dnsRecordProvider) checkDNSResourceReady(domain string, _ []string) bool {
	entry := p.prepareEntry(domain)
	obj, err := p.dnsrecordResources.Get_(entry)
	if err != nil {
		return true // no more waiting
	}
	entry = obj.Data().(*extensionsv1alpha.DNSRecord)
	p.entries[domain] = entry
	return entry.Status.LastOperation != nil && entry.Status.LastOperation.State == v1beta1.LastOperationStateSucceeded &&
		entry.Generation == entry.Status.ObservedGeneration
}

func (p *dnsRecordProvider) failedDNSResourceReadyMessage(final bool) string {
	if final {
		var errs []error
		for key, entry := range p.entries {
			switch {
			case entry.Status.LastOperation == nil:
				errs = append(errs, fmt.Errorf("no provider found to apply DNSRecord for %s", key))
			case entry.Status.LastOperation.State == v1beta1.LastOperationStateSucceeded:
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

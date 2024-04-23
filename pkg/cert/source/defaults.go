/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package source

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller"
	"github.com/gardener/controller-manager-library/pkg/controllermanager/controller/reconcile"
	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
)

////////////////////////////////////////////////////////////////////////////////
// EventFeedback
////////////////////////////////////////////////////////////////////////////////

// EventFeedback is struct to store events
type EventFeedback struct {
	logger logger.LogContext
	source resources.Object
	events map[string]string
}

// NewEventFeedback creates a new EventFeedback
func NewEventFeedback(logger logger.LogContext, obj resources.Object, events map[string]string) CertFeedback {
	return &EventFeedback{logger, obj, events}
}

// Ready adds a ready event
func (f *EventFeedback) Ready(info *CertInfo, msg string) {
	if msg == "" {
		msg = "cert request is ready"
	}
	f.event(info, msg)
}

// Pending adds a pending event.
func (f *EventFeedback) Pending(info *CertInfo, msg string) {
	if msg == "" {
		msg = "cert request is pending"
	}
	f.event(info, msg)
}

// Failed adds a failed event.
func (f *EventFeedback) Failed(info *CertInfo, err error) {
	if err == nil {
		err = fmt.Errorf("cert request is errornous")
	}
	f.event(info, err.Error(), true)
}

// Succeeded addas a succeeded event.
func (f *EventFeedback) Succeeded() {
}

func (f *EventFeedback) event(info *CertInfo, msg string, warning ...bool) {
	channel := ""
	if info != nil {
		channel = info.SecretName
		if info.SecretNamespace != nil {
			channel = *info.SecretNamespace + "/" + info.SecretName
		}
	}
	if msg != f.events[channel] {
		key := f.source.ClusterKey()
		eventType := v1.EventTypeNormal
		if len(warning) > 0 && warning[0] {
			eventType = v1.EventTypeWarning
		}
		f.events[channel] = msg
		if channel != "" {
			f.logger.Infof("event for %q(%s): %s", key, channel, msg)
			f.source.Event(eventType, "cert-annotation",
				fmt.Sprintf("%s: %s", channel, msg))
		} else {
			f.logger.Infof("event for %q: %s", key, msg)
			f.source.Event(eventType, "cert-annotation", msg)
		}
	}
}

////////////////////////////////////////////////////////////////////////////////
// CertSource
////////////////////////////////////////////////////////////////////////////////

// DefaultCertSource is the standard CertSource implementation.
type DefaultCertSource struct {
	lock    sync.Mutex
	handler CertTargetExtractor
	Events  map[resources.ClusterObjectKey]map[string]string
}

var _ CertSource = &DefaultCertSource{}

// NewDefaultCertSource creates a DefaultCertSource
func NewDefaultCertSource(handler CertTargetExtractor) DefaultCertSource {
	return DefaultCertSource{handler: handler, Events: map[resources.ClusterObjectKey]map[string]string{}}
}

// Name is the name
func (t *certsourcetype) Name() string {
	return t.name
}

// GroupKind is the group kind
func (t *certsourcetype) GroupKind() schema.GroupKind {
	return t.kind
}

// Create creates a CertSource.
func (t *handlercertsourcetype) Create(_ controller.Interface) (CertSource, error) {
	return t, nil
}

// Create creates a CertSource.
func (t *creatorcertsourcetype) Create(c controller.Interface) (CertSource, error) {
	return t.handler(c)
}

// Setup is the setup method.
func (s *DefaultCertSource) Setup() error {
	return nil
}

// Start is the start method.
func (s *DefaultCertSource) Start() error {
	return nil
}

// GetEvents returns the events for a cluster object key.
func (s *DefaultCertSource) GetEvents(key resources.ClusterObjectKey) map[string]string {
	s.lock.Lock()
	defer s.lock.Unlock()
	events := s.Events[key]
	if events == nil {
		events = map[string]string{}
		s.Events[key] = events
	}
	return events
}

// NewCertsInfo creates a CertsInfo
func NewCertsInfo() *CertsInfo {
	return &CertsInfo{Certs: map[string]CertInfo{}}
}

// CreateCertFeedback creates an event feedback for the given object.
func (s *DefaultCertSource) CreateCertFeedback(logger logger.LogContext, obj resources.Object) CertFeedback {
	events := s.GetEvents(obj.ClusterKey())
	return NewEventFeedback(logger, obj, events)
}

// GetCertsInfo fills a CertsInfo for an object.
func (s *DefaultCertSource) GetCertsInfo(logger logger.LogContext, objData resources.ObjectData) (*CertsInfo, error) {
	info := NewCertsInfo()
	secretName, err := s.handler(logger, objData)
	if err != nil {
		logger.Debug(err.Error())
		return nil, nil
	}

	annotatedDomains, _ := GetDomainsFromAnnotations(objData)
	if annotatedDomains == nil {
		logger.Debug("No dnsnames or commonname annotations")
		return nil, nil
	}

	var issuer *string
	annotatedIssuer, ok := resources.GetAnnotation(objData, AnnotIssuer)
	if ok {
		issuer = &annotatedIssuer
	}

	followCNAME := false
	if value, ok := resources.GetAnnotation(objData, AnnotFollowCNAME); ok {
		followCNAME, _ = strconv.ParseBool(value)
	}
	preferredChain, _ := resources.GetAnnotation(objData, AnnotPreferredChain)

	algorithm, _ := resources.GetAnnotation(objData, AnnotPrivateKeyAlgorithm)
	keySize := 0
	if keySizeStr, ok := resources.GetAnnotation(objData, AnnotPrivateKeySize); ok {
		if value, err := strconv.Atoi(keySizeStr); err == nil {
			keySize = value
		}
	}

	info.Certs[secretName] = CertInfo{
		SecretName:          secretName,
		Domains:             annotatedDomains,
		IssuerName:          issuer,
		FollowCNAME:         followCNAME,
		SecretLabels:        ExtractSecretLabels(objData),
		PreferredChain:      preferredChain,
		PrivateKeyAlgorithm: algorithm,
		PrivateKeySize:      keySize,
	}
	return info, nil
}

// Delete deleted a object.
func (s *DefaultCertSource) Delete(logger logger.LogContext, obj resources.Object) reconcile.Status {
	s.Deleted(logger, obj.ClusterKey())
	return reconcile.Succeeded(logger)
}

// Deleted performs cleanup.
func (s *DefaultCertSource) Deleted(_ logger.LogContext, key resources.ClusterObjectKey) {
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.Events, key)
}

// GetDomainsFromAnnotations gets includes annotated DNS names (DNS names from annotation "cert.gardener.cloud/dnsnames"
// or alternatively "dns.gardener.cloud/dnsnames") and the optional common name.
// The common name is added to the returned domain list
func GetDomainsFromAnnotations(objData resources.ObjectData) (annotatedDomains []string, cn string) {
	a, ok := resources.GetAnnotation(objData, AnnotCertDNSNames)
	if !ok {
		a, ok = resources.GetAnnotation(objData, AnnotDnsnames)
		if a == "*" || a == "all" {
			a = ""
			ok = false
		}
		if !ok {
			_, ok = resources.GetAnnotation(objData, AnnotCommonName)
			if !ok {
				return nil, ""
			}
		}
	}

	cn, _ = resources.GetAnnotation(objData, AnnotCommonName)
	cn = strings.TrimSpace(cn)
	annotatedDomains = []string{}
	if cn != "" {
		annotatedDomains = append(annotatedDomains, cn)
	}
	for _, e := range strings.Split(a, ",") {
		e = strings.TrimSpace(e)
		if e != "" && e != cn {
			annotatedDomains = append(annotatedDomains, e)
		}
	}
	return annotatedDomains, cn
}

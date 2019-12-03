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

package source

import (
	"fmt"
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
		msg = fmt.Sprintf("cert request is ready")
	}
	f.event(info, msg)
}

// Pending adds a pending event.
func (f *EventFeedback) Pending(info *CertInfo, msg string) {
	if msg == "" {
		msg = fmt.Sprintf("cert request is pending")
	}
	f.event(info, msg)
}

// Failed adds a failed event.
func (f *EventFeedback) Failed(info *CertInfo, err error) {
	if err == nil {
		err = fmt.Errorf("cert request is errornous")
	}
	f.event(info, err.Error())
}

// Succeeded addas a succeeded event.
func (f *EventFeedback) Succeeded() {
}

func (f *EventFeedback) event(info *CertInfo, msg string) {
	channel := ""
	if info != nil {
		channel = info.SecretName
	}
	if msg != f.events[channel] {
		key := f.source.ClusterKey()
		f.events[channel] = msg
		if channel != "" {
			f.logger.Infof("event for %q(%s): %s", key, channel, msg)
			f.source.Event(v1.EventTypeNormal, "cert-annotation",
				fmt.Sprintf("%s: %s", channel, msg))
		} else {
			f.logger.Infof("event for %q: %s", key, msg)
			f.source.Event(v1.EventTypeNormal, "cert-annotation", msg)
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
func NewDefaultCertSource(handler CertTargetExtractor, _ schema.GroupKind) DefaultCertSource {
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
func (t *handlercertsourcetype) Create(c controller.Interface) (CertSource, error) {
	return t, nil
}

// Create creates a CertSource.
func (t *creatorcertsourcetype) Create(c controller.Interface) (CertSource, error) {
	return t.handler(c)
}

// Setup is the setup method.
func (s *DefaultCertSource) Setup() {
}

// Start is the start method.
func (s *DefaultCertSource) Start() {
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
func (s *DefaultCertSource) NewCertsInfo(logger logger.LogContext, obj resources.Object) *CertsInfo {
	events := s.GetEvents(obj.ClusterKey())
	return &CertsInfo{Certs: map[string]CertInfo{}, Feedback: NewEventFeedback(logger, obj, events)}
}

// GetCertsInfo fills a CertsInfo for an object.
func (s *DefaultCertSource) GetCertsInfo(logger logger.LogContext, obj resources.Object, current *CertCurrentState) (*CertsInfo, error) {
	info := s.NewCertsInfo(logger, obj)
	secretName, err := s.handler(logger, obj, current)
	a, ok := resources.GetAnnotation(obj.Data(), AnnotDnsnames)
	if err != nil || !ok {
		return nil, nil
	}

	annotatedDomains := []string{}
	for _, e := range strings.Split(a, ",") {
		e = strings.TrimSpace(e)
		if e != "" {
			annotatedDomains = append(annotatedDomains, e)
		}
	}

	var issuer *string
	annotatedIssuer, ok := resources.GetAnnotation(obj.Data(), AnnotIssuer)
	if ok {
		issuer = &annotatedIssuer
	}

	info.Certs[secretName] = CertInfo{SecretName: secretName, Domains: annotatedDomains, IssuerName: issuer}
	return info, nil
}

// Delete deleted a object.
func (s *DefaultCertSource) Delete(logger logger.LogContext, obj resources.Object) reconcile.Status {
	s.Deleted(logger, obj.ClusterKey())
	return reconcile.Succeeded(logger)
}

// Deleted performs cleanup.
func (s *DefaultCertSource) Deleted(logger logger.LogContext, key resources.ClusterObjectKey) {
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.Events, key)
}

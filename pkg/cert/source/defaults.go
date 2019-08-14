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

type EventFeedback struct {
	logger logger.LogContext
	source resources.Object
	events map[string]string
}

func NewEventFeedback(logger logger.LogContext, obj resources.Object, events map[string]string) CertFeedback {
	return &EventFeedback{logger, obj, events}
}

func (this *EventFeedback) Ready(info *CertInfo, msg string) {
	if msg == "" {
		msg = fmt.Sprintf("cert request is ready")
	}
	this.event(info, msg)
}

func (this *EventFeedback) Pending(info *CertInfo, msg string) {
	if msg == "" {
		msg = fmt.Sprintf("cert request is pending")
	}
	this.event(info, msg)
}

func (this *EventFeedback) Failed(info *CertInfo, err error) {
	if err == nil {
		err = fmt.Errorf("cert request is errornous")
	}
	this.event(info, err.Error())
}

func (this *EventFeedback) Succeeded() {
}

func (this *EventFeedback) event(info *CertInfo, msg string) {
	channel := ""
	if info != nil {
		channel = info.SecretName
	}
	if msg != this.events[channel] {
		key := this.source.ClusterKey()
		this.events[channel] = msg
		if channel != "" {
			this.logger.Infof("event for %q(%s): %s", key, channel, msg)
			this.source.Event(v1.EventTypeNormal, "cert-annotation",
				fmt.Sprintf("%s: %s", channel, msg))
		} else {
			this.logger.Infof("event for %q: %s", key, msg)
			this.source.Event(v1.EventTypeNormal, "cert-annotation", msg)
		}
	}
}

////////////////////////////////////////////////////////////////////////////////
// CertSource
////////////////////////////////////////////////////////////////////////////////

type DefaultCertSource struct {
	lock    sync.Mutex
	handler CertTargetExtractor
	Events  map[resources.ClusterObjectKey]map[string]string
}

var _ CertSource = &DefaultCertSource{}

func NewDefaultCertSource(handler CertTargetExtractor, _ schema.GroupKind) DefaultCertSource {
	return DefaultCertSource{handler: handler, Events: map[resources.ClusterObjectKey]map[string]string{}}
}

func (this *certsourcetype) Name() string {
	return this.name
}

func (this *certsourcetype) GroupKind() schema.GroupKind {
	return this.kind
}

func (this *handlercertsourcetype) Create(c controller.Interface) (CertSource, error) {
	return this, nil
}

func (this *creatorcertsourcetype) Create(c controller.Interface) (CertSource, error) {
	return this.handler(c)
}

func (this *DefaultCertSource) Setup() {
}

func (this *DefaultCertSource) Start() {
}

func (this *DefaultCertSource) GetEvents(key resources.ClusterObjectKey) map[string]string {
	this.lock.Lock()
	defer this.lock.Unlock()
	events := this.Events[key]
	if events == nil {
		events = map[string]string{}
		this.Events[key] = events
	}
	return events
}

func (this *DefaultCertSource) NewCertsInfo(logger logger.LogContext, obj resources.Object) *CertsInfo {
	events := this.GetEvents(obj.ClusterKey())
	return &CertsInfo{Certs: map[string]CertInfo{}, Feedback: NewEventFeedback(logger, obj, events)}
}

func (this *DefaultCertSource) GetCertsInfo(logger logger.LogContext, obj resources.Object, current *CertCurrentState) (*CertsInfo, error) {
	info := this.NewCertsInfo(logger, obj)
	secretName, err := this.handler(logger, obj, current)
	a, ok := resources.GetAnnotation(obj.Data(), ANNOT_DNSNAMES)
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
	annotatedIssuer, ok := resources.GetAnnotation(obj.Data(), ANNOT_ISSUER)
	if ok {
		issuer = &annotatedIssuer
	}

	info.Certs[secretName] = CertInfo{SecretName: secretName, Domains: annotatedDomains, IssuerName: issuer}
	return info, nil
}

func (this *DefaultCertSource) Delete(logger logger.LogContext, obj resources.Object) reconcile.Status {
	this.Deleted(logger, obj.ClusterKey())
	return reconcile.Succeeded(logger)
}

func (this *DefaultCertSource) Deleted(logger logger.LogContext, key resources.ClusterObjectKey) {
	this.lock.Lock()
	defer this.lock.Unlock()
	delete(this.Events, key)
}

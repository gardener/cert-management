/*
 * Copyright 2019 SAP SE or an SAP affiliate company. All rights reserved. ur file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use ur file except in compliance with the License.
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

package core

import (
	"github.com/gardener/controller-manager-library/pkg/resources"
	v1 "k8s.io/api/core/v1"
)

type State struct {
	secrets      *ReferencedSecrets
	certificates *AssociatedObjects
}

func NewState() *State {
	return &State{secrets: NewReferencedSecrets(), certificates: NewAssociatedObjects()}
}

func (s *State) RemoveIssuer(name resources.ObjectName) bool {
	return s.secrets.RemoveIssuer(name)
}

func (s *State) AddCertAssoc(issuer resources.ObjectName, cert resources.ObjectName) {
	s.certificates.AddDest(issuer, cert)
}

func (s *State) RemoveCertAssoc(issuer resources.ObjectName, cert resources.ObjectName) {
	s.certificates.RemoveDest(issuer, cert)
}

func (s *State) CertificateNamesForIssuer(issuer resources.ObjectName) []resources.ObjectName {
	return s.certificates.DestinationsAsArray(issuer)
}

func (s *State) IssuerNamesForSecret(secretName resources.ObjectName) resources.ObjectNameSet {
	return s.secrets.IssuerNamesFor(secretName)
}

func (s *State) RememberIssuerSecret(issuer resources.ObjectName, secretRef *v1.SecretReference) {
	s.secrets.RememberIssuerSecret(issuer, secretRef)
}

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

package core

import (
	"fmt"
	"github.com/gardener/controller-manager-library/pkg/resources"
	"sort"
	"strings"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
)

func TestRobustRemember(t *testing.T) {
	table := []struct {
		command         string
		issuerName      string
		secretName      string
		secretHash      string
		expectedChange  bool
		expectedContent string
	}{
		{"add", "A", "", "", false, ""},
		{"add", "A", "s", "h1", true, "s:A"},
		{"add", "A", "s", "h1", false, "s:A"},
		{"add", "A", "s", "h2", true, "s:A"},
		{"add", "B", "s", "h", true, "s:A,B"},
		{"add", "C", "t", "h", true, "s:A,B;t:C"},
		{"add", "D", "s", "h", true, "s:A,B,D;t:C"},
		{"add", "B", "u", "h", true, "s:A,D;t:C;u:B"},
		{"remove", "B", "", "h", true, "s:A,D;t:C"},
		{"remove", "B", "", "h", false, "s:A,D;t:C"},
		{"removeSecret", "", "s", "h", true, "t:C"},
		{"removeSecret", "", "s", "h", false, "t:C"},
	}
	data := NewReferencedSecrets()
	for _, entry := range table {
		changed := false
		switch entry.command {
		case "add":
			issuer := &api.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      entry.issuerName,
					Namespace: "",
				},
				Spec: api.IssuerSpec{ACME: &api.ACMESpec{}},
			}
			if entry.secretName != "" {
				issuer.Spec.ACME.PrivateKeySecretRef = &v1.SecretReference{
					Namespace: "default",
					Name:      entry.secretName,
				}
			}
			changed = data.RememberIssuerSecret(resources.NewObjectName("default", entry.issuerName),
				issuer.Spec.ACME.PrivateKeySecretRef, entry.secretHash)
		case "remove":
			changed = data.RemoveIssuer(resources.NewObjectName("default", entry.issuerName))
		case "removeSecret":
			issuers := data.IssuerNamesFor(resources.NewObjectName("default", entry.secretName))
			for issuer := range issuers {
				b := data.RemoveIssuer(issuer)
				changed = changed || b
			}
		}
		if changed != entry.expectedChange {
			t.Errorf("%s %s/%s change != %t", entry.command, entry.issuerName, entry.secretName, entry.expectedChange)
		}
		content := testContent(data)
		if content != entry.expectedContent {
			t.Errorf("%s %s/%s content mismatch %s != %s", entry.command, entry.issuerName, entry.secretName, content, entry.expectedContent)
		}
	}
}

func testContent(data *ReferencedSecrets) string {
	secrets := []string{}
	for s := range data.secretToIssuers {
		secrets = append(secrets, s.Name())
	}
	sort.Strings(secrets)

	parts := []string{}
	for _, s := range secrets {
		issuers := []string{}
		for issuer := range data.secretToIssuers[resources.NewObjectName("default", s)] {
			issuers = append(issuers, issuer.Name())
		}
		sort.Strings(issuers)
		part := fmt.Sprintf("%s:%s", s, strings.Join(issuers, ","))
		parts = append(parts, part)
	}
	return strings.Join(parts, ";")
}

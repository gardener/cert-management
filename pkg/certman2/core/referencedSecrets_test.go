/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package core

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
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
			issuer := &v1alpha1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      entry.issuerName,
					Namespace: "test",
				},
				Spec: v1alpha1.IssuerSpec{ACME: &v1alpha1.ACMESpec{}},
			}
			if entry.secretName != "" {
				issuer.Spec.ACME.PrivateKeySecretRef = &v1.SecretReference{
					Namespace: "test",
					Name:      entry.secretName,
				}
			}
			changed = data.RememberIssuerSecret(secondaryIssuerKey(entry.issuerName),
				issuer.Spec.ACME.PrivateKeySecretRef, entry.secretHash)
		case "remove":
			changed = data.RemoveIssuer(secondaryIssuerKey(entry.issuerName))
		case "removeSecret":
			issuers := data.IssuerNamesFor(secondaryIssuerSecretKey(entry.secretName))
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
		secrets = append(secrets, s.ObjectKey.Name)
	}
	sort.Strings(secrets)

	parts := []string{}
	for _, s := range secrets {
		issuers := []string{}
		for issuer := range data.secretToIssuers[secondaryIssuerSecretKey(s)] {
			issuers = append(issuers, issuer.ObjectKey.Name)
		}
		sort.Strings(issuers)
		part := fmt.Sprintf("%s:%s", s, strings.Join(issuers, ","))
		parts = append(parts, part)
	}
	return strings.Join(parts, ";")
}

func secondaryIssuerKey(name string) IssuerKey {
	return NewIssuerKey(client.ObjectKey{Namespace: "test", Name: name}, true)
}

func secondaryIssuerSecretKey(name string) SecretKey {
	return NewSecretKey(client.ObjectKey{Namespace: "test", Name: name}, true)
}

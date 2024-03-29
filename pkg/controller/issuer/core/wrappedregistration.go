/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package core

import (
	"encoding/json"

	"github.com/go-acme/lego/v4/registration"
	"k8s.io/apimachinery/pkg/runtime"
)

type wrappedRegistration struct {
	registration.Resource `json:",inline"`
	SecretHash            *string `json:"secretHash,omitempty"`
}

// WrapRegistration wraps registration
func WrapRegistration(raw []byte, secretHash string) ([]byte, error) {
	reg := &wrappedRegistration{}
	err := json.Unmarshal(raw, reg)
	if err != nil {
		return nil, err
	}
	reg.SecretHash = &secretHash
	return json.Marshal(&reg)
}

// IsSameExistingRegistration returns true if status ACME has same secret hash
// or if it has in the old format without secret hash (for migration)
func IsSameExistingRegistration(raw *runtime.RawExtension, realSecretHash string) bool {
	if raw == nil || raw.Raw == nil {
		return false
	}
	reg := &wrappedRegistration{}
	if err := json.Unmarshal(raw.Raw, reg); err == nil && reg.SecretHash != nil {
		return *reg.SecretHash == realSecretHash
	}
	return true
}

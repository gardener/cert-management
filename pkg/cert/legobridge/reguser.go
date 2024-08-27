/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package legobridge

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/gardener/cert-management/pkg/cert/metrics"
	"github.com/gardener/cert-management/pkg/cert/utils"

	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

const (
	// KeyPrivateKey is the secret data key for the private key.
	KeyPrivateKey = "privateKey"
	// KeyHmacKey is the secret data key for the MAC key for external account binding.
	KeyHmacKey = "hmacKey"
)

// RegistrationUser contains the data of a registration user.
type RegistrationUser struct {
	email        string
	caDirURL     string
	registration *registration.Resource
	key          crypto.PrivateKey

	eabKeyID   string
	eabHmacKey string
}

// GetEmail returns the email of the registration user.
func (u *RegistrationUser) GetEmail() string {
	return u.email
}

// GetRegistration returns the registration resource.
func (u *RegistrationUser) GetRegistration() *registration.Resource {
	return u.registration
}

// GetPrivateKey returns the private key of the registration user.
func (u *RegistrationUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// EabHmacKey returns the MAC key if it is an external account binding
func (u *RegistrationUser) EabHmacKey() string {
	return u.eabHmacKey
}

// EabKeyID returns the key ID if it is an external account binding
func (u *RegistrationUser) EabKeyID() string {
	return u.eabKeyID
}

// CADirURL returns the URL of the ACME directory server
func (u *RegistrationUser) CADirURL() string {
	return u.caDirURL
}

// NewConfig creates a new lego config.
func (u *RegistrationUser) NewConfig(caDirURL string) *lego.Config {
	config := lego.NewConfig(u)
	config.CADirURL = caDirURL
	return config
}

// NewRegistrationUserFromEmail generates a private key and requests a new registration for the user.
func NewRegistrationUserFromEmail(issuerKey utils.IssuerKeyItf,
	email string, caDirURL string, secretData map[string][]byte, eabKeyID, eabHmacKey string,
) (*RegistrationUser, error) {
	privateKey, err := ExtractOrGeneratePrivateKey(secretData)
	if err != nil {
		return nil, err
	}

	return NewRegistrationUserFromEmailAndPrivateKey(issuerKey, email, caDirURL, privateKey, eabKeyID, eabHmacKey)
}

// ExtractOrGeneratePrivateKey extracts the private key from the secret or generates a new one.
func ExtractOrGeneratePrivateKey(secretData map[string][]byte) (crypto.PrivateKey, error) {
	privkeyData, ok := secretData[KeyPrivateKey]
	var privateKey crypto.PrivateKey
	var err error
	if ok {
		privateKey, err = bytesToPrivateKey(privkeyData)
	} else {
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// NewRegistrationUserFromEmailAndPrivateKey requests a user registration.
func NewRegistrationUserFromEmailAndPrivateKey(issuerKey utils.IssuerKeyItf,
	email string, caDirURL string, privateKey crypto.PrivateKey, eabKid, eabHmacKey string,
) (*RegistrationUser, error) {
	user := &RegistrationUser{email: email, key: privateKey, caDirURL: caDirURL, eabKeyID: eabKid, eabHmacKey: eabHmacKey}
	config := user.NewConfig(caDirURL)

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}
	var reg *registration.Resource
	// New users will need to register
	if eabKid == "" {
		reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	} else {
		reg, err = client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  user.eabKeyID,
			HmacEncoded:          user.eabHmacKey,
		})
	}
	if err != nil {
		return user, err
	}
	user.registration = reg

	metrics.AddACMEAccountRegistration(issuerKey, reg.URI, email)

	return user, nil
}

// ToSecretData returns the registration user as a secret data map.
func (u *RegistrationUser) ToSecretData() (map[string][]byte, error) {
	privkey, err := privateKeyToBytes(u.key)
	if err != nil {
		return nil, fmt.Errorf("encoding private key failed: %w", err)
	}
	return map[string][]byte{KeyPrivateKey: privkey}, nil
}

// RawRegistration returns the registration as a byte array.
func (u *RegistrationUser) RawRegistration() ([]byte, error) {
	reg, err := json.Marshal(u.registration)
	if err != nil {
		return nil, fmt.Errorf("encoding registration failed: %w", err)
	}
	return reg, nil
}

// RegistrationUserFromSecretData restores a RegistrationUser from a secret data map.
func RegistrationUserFromSecretData(issuerKey utils.IssuerKeyItf,
	email, caDirURL string, registrationRaw []byte, data map[string][]byte, eabKeyID, eabHmacKey string,
) (*RegistrationUser, error) {
	privkeyBytes, ok := data[KeyPrivateKey]
	if !ok {
		return nil, fmt.Errorf("`%s` data not found in secret", KeyPrivateKey)
	}
	privateKey, err := bytesToPrivateKey(privkeyBytes)
	if err != nil {
		return nil, err
	}

	reg := &registration.Resource{}
	err = json.Unmarshal(registrationRaw, reg)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling registration json failed: %w", err)
	}
	if reg.URI == "" {
		return nil, fmt.Errorf("unmarshalling registration with unexpected empty URI")
	}
	metrics.AddACMEAccountRegistration(issuerKey, reg.URI, email)
	return &RegistrationUser{
		email: email, registration: reg, caDirURL: caDirURL, key: privateKey,
		eabKeyID: eabKeyID, eabHmacKey: eabHmacKey,
	}, nil
}

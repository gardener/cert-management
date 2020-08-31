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
	"net/url"

	"github.com/gardener/cert-management/pkg/cert/metrics"

	"github.com/go-acme/lego/v3/lego"
	"github.com/go-acme/lego/v3/registration"
)

const (
	// KeyPrivateKey is the secret data key for the private key.
	KeyPrivateKey = "privateKey"
)

// RegistrationUser contains the data of a registration user.
type RegistrationUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

// GetEmail returns the email of the registration user.
func (u *RegistrationUser) GetEmail() string {
	return u.Email
}

// GetRegistration returns the registration resource.
func (u *RegistrationUser) GetRegistration() *registration.Resource {
	return u.Registration
}

// GetPrivateKey returns the private key of the registration user.
func (u *RegistrationUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// NewConfig creates a new lego config.
func (u *RegistrationUser) NewConfig(caDirURL string) *lego.Config {
	config := lego.NewConfig(u)
	config.CADirURL = caDirURL
	return config
}

// NewRegistrationUserFromEmail generates a private key and requests a new registration for the user.
func NewRegistrationUserFromEmail(email string, caDirURL string, secretData map[string][]byte) (*RegistrationUser, error) {
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

	return NewRegistrationUserFromEmailAndPrivateKey(email, caDirURL, privateKey)
}

// NewRegistrationUserFromEmailAndPrivateKey requests a user registration.
func NewRegistrationUserFromEmailAndPrivateKey(email string, caDirURL string, privateKey crypto.PrivateKey) (*RegistrationUser, error) {
	user := &RegistrationUser{Email: email, key: privateKey}
	config := user.NewConfig(caDirURL)

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}
	// New users will need to register
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return user, err
	}
	user.Registration = reg

	server := "unknown"
	urlObj, err := url.Parse(caDirURL)
	if urlObj != nil {
		server = urlObj.Host
	}
	metrics.AddACMEAccountRegistration(server, email)

	return user, nil
}

// ToSecretData returns the registration user as a secret data map.
func (u *RegistrationUser) ToSecretData() (map[string][]byte, error) {
	privkey, err := privateKeyToBytes(u.key)
	if err != nil {
		return nil, fmt.Errorf("encoding private key failed: %s", err.Error())
	}
	return map[string][]byte{KeyPrivateKey: privkey}, nil
}

// RawRegistration returns the registration as a byte array.
func (u *RegistrationUser) RawRegistration() ([]byte, error) {
	reg, err := json.Marshal(u.Registration)
	if err != nil {
		return nil, fmt.Errorf("encoding registration failed: %s", err.Error())
	}
	return reg, nil
}

// RegistrationUserFromSecretData restores a RegistrationUser from a secret data map.
func RegistrationUserFromSecretData(email string, registrationRaw []byte, data map[string][]byte) (*RegistrationUser, error) {
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
		return nil, fmt.Errorf("unmarshalling registration json failed with %s", err.Error())
	}
	return &RegistrationUser{Email: email, Registration: reg, key: privateKey}, nil
}

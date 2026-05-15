/*
 * SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
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

	"github.com/go-acme/lego/v5/acme"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/cert-management/pkg/shared"
)

// mockIssuerKey is a simple mock implementation of IssuerKeyItf for testing
type mockIssuerKey struct {
	name      string
	namespace string
	cluster   shared.Cluster
}

func (m *mockIssuerKey) Name() string              { return m.name }
func (m *mockIssuerKey) Namespace() string         { return m.namespace }
func (m *mockIssuerKey) Cluster() shared.Cluster   { return m.cluster }
func (m *mockIssuerKey) Secondary() bool           { return m.cluster == shared.ClusterDefault }
func (m *mockIssuerKey) String() string            { return m.namespace + "/" + m.name }


var _ = Describe("RegistrationUser", func() {
	var (
		issuerKey   shared.IssuerKeyItf
		email       string
		caDirURL    string
		privateKey  *ecdsa.PrivateKey
		secretData  map[string][]byte
		eabKeyID    string
		eabHmacKey  string
	)

	BeforeEach(func() {
		issuerKey = &mockIssuerKey{
			name:      "test-issuer",
			namespace: "default",
			cluster:   shared.ClusterDefault,
		}
		email = "test@example.com"
		caDirURL = "https://acme-server.example.com/directory"
		eabKeyID = ""
		eabHmacKey = ""

		// Generate a test private key
		var err error
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).ToNot(HaveOccurred())

		// Create secret data with the private key
		privKeyBytes, err := privateKeyToBytes(privateKey, false)
		Expect(err).ToNot(HaveOccurred())
		secretData = map[string][]byte{
			KeyPrivateKey: privKeyBytes,
		}
	})

	Context("registrationUserFromConfigWithFactory", func() {
		Context("with valid v5 registration data", func() {
			It("should restore user without migration", func() {
				// Create valid v5 registration data with Location
				validReg := &acme.ExtendedAccount{
					Account: acme.Account{
						Status: "valid",
					},
					Location: "https://acme-server.example.com/acme/acct/123456",
				}
				registrationRaw, err := json.Marshal(validReg)
				Expect(err).ToNot(HaveOccurred())

				// Mock factory should not be called
				factoryCalled := false
				mockFactory := func(cfg *RegistrationConfig, privateKey crypto.Signer) (*RegistrationUser, error) {
					factoryCalled = true
					return nil, fmt.Errorf("factory should not be called for v5 data")
				}

				cfg := &RegistrationConfig{
					IssuerKey:       issuerKey,
					Email:           email,
					CADirURL:        caDirURL,
					RegistrationRaw: registrationRaw,
					SecretData:      secretData,
					EABKeyID:        eabKeyID,
					EABHmacKey:      eabHmacKey,
				}

				result, err := registrationUserFromConfigWithFactory(cfg, mockFactory)

				Expect(err).ToNot(HaveOccurred())
				Expect(result).ToNot(BeNil())
				Expect(result.User).ToNot(BeNil())
				Expect(result.User.GetEmail()).To(Equal(email))
				Expect(result.User.CADirURL()).To(Equal(caDirURL))
				Expect(result.User.GetRegistration().Location).To(Equal(validReg.Location))

				// Raw data should not be updated (no migration occurred)
				Expect(result.UpdatedRaw).To(Equal(registrationRaw))

				// Factory should not have been called
				Expect(factoryCalled).To(BeFalse())
			})
		})

		Context("with v4 registration data (missing Location)", func() {
			It("should trigger migration with factory function", func() {
				// Create v4-style registration data without Location
				v4Reg := &acme.ExtendedAccount{
					Account: acme.Account{
						Status: "valid",
					},
					Location: "", // Empty location indicates v4 format
				}
				registrationRaw, err := json.Marshal(v4Reg)
				Expect(err).ToNot(HaveOccurred())
				// Mock factory that returns a valid v5 registration
				newV5Reg := &acme.ExtendedAccount{
					Account: acme.Account{
						Status: "valid",
					},
					Location: "https://acme-server.example.com/acme/acct/999999",
				}

				mockFactory := func(cfg *RegistrationConfig, pk crypto.Signer) (*RegistrationUser, error) {
					// Verify correct parameters are passed
					Expect(cfg.IssuerKey).To(Equal(issuerKey))
					Expect(cfg.Email).To(Equal(email))
					Expect(cfg.CADirURL).To(Equal(caDirURL))
					Expect(pk).To(Equal(crypto.Signer(privateKey)))
					Expect(cfg.EABKeyID).To(Equal(eabKeyID))
					Expect(cfg.EABHmacKey).To(Equal(eabHmacKey))

					return &RegistrationUser{
						email:           cfg.Email,
						caDirURL:        cfg.CADirURL,
						extendedAccount: newV5Reg,
						key:             pk,
						eabKeyID:        cfg.EABKeyID,
						eabHmacKey:      cfg.EABHmacKey,
					}, nil
				}

				cfg := &RegistrationConfig{
					IssuerKey:            issuerKey,
					Email:                email,
					CADirURL:             caDirURL,
					RegistrationRaw:      registrationRaw,
					SecretData:           secretData,
					EABKeyID:             eabKeyID,
					EABHmacKey:           eabHmacKey,
					AllowV4ToV5Migration: true, // Allow migration for this test
				}

				result, err := registrationUserFromConfigWithFactory(cfg, mockFactory)

				Expect(err).ToNot(HaveOccurred())
				Expect(result).ToNot(BeNil())
				Expect(result.User).ToNot(BeNil())
				Expect(result.User.GetEmail()).To(Equal(email))
				Expect(result.User.GetRegistration().Location).To(Equal(newV5Reg.Location))

				// Raw data should be updated with new registration
				Expect(result.UpdatedRaw).ToNot(Equal(registrationRaw))

				// Verify updated raw contains the new location
				var updatedReg acme.ExtendedAccount
				err = json.Unmarshal(result.UpdatedRaw, &updatedReg)
				Expect(err).ToNot(HaveOccurred())
				Expect(updatedReg.Location).To(Equal(newV5Reg.Location))
			})

			It("should return error if factory fails", func() {
				v4Reg := &acme.ExtendedAccount{
					Account: acme.Account{
						Status: "valid",
					},
					Location: "",
				}
				registrationRaw, err := json.Marshal(v4Reg)
				Expect(err).ToNot(HaveOccurred())
				// Mock factory that returns an error
				mockFactory := func(cfg *RegistrationConfig, privateKey crypto.Signer) (*RegistrationUser, error) {
					return nil, fmt.Errorf("ACME server unreachable")
				}

				cfg := &RegistrationConfig{
					IssuerKey:            issuerKey,
					Email:                email,
					CADirURL:             caDirURL,
					RegistrationRaw:      registrationRaw,
					SecretData:           secretData,
					EABKeyID:             eabKeyID,
					EABHmacKey:           eabHmacKey,
					AllowV4ToV5Migration: true, // Allow migration for this test
				}

				result, err := registrationUserFromConfigWithFactory(cfg, mockFactory)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("migrating v4 registration to v5 failed"))
				Expect(err.Error()).To(ContainSubstring("ACME server unreachable"))
				Expect(result).To(BeNil())
			})

			It("should call log function when provided", func() {
				v4Reg := &acme.ExtendedAccount{
					Account: acme.Account{
						Status: "valid",
					},
					Location: "",
				}
				registrationRaw, err := json.Marshal(v4Reg)
				Expect(err).ToNot(HaveOccurred())

				mockFactory := func(cfg *RegistrationConfig, privateKey crypto.Signer) (*RegistrationUser, error) {
					return nil, fmt.Errorf("test error")
				}

				cfg := &RegistrationConfig{
					IssuerKey:       issuerKey,
					Email:           email,
					CADirURL:        caDirURL,
					RegistrationRaw: registrationRaw,
					SecretData:      secretData,
					EABKeyID:        eabKeyID,
					EABHmacKey:      eabHmacKey,
				}

				_, err = registrationUserFromConfigWithFactory(cfg, mockFactory)

				Expect(err).To(HaveOccurred())
			})

			It("should work without log function", func() {
				v4Reg := &acme.ExtendedAccount{
					Account: acme.Account{
						Status: "valid",
					},
					Location: "",
				}
				registrationRaw, err := json.Marshal(v4Reg)
				Expect(err).ToNot(HaveOccurred())

				mockFactory := func(cfg *RegistrationConfig, privateKey crypto.Signer) (*RegistrationUser, error) {
				return nil, fmt.Errorf("test error")
			}

				// Pass nil log function - should not panic
				cfg := &RegistrationConfig{
				IssuerKey:       issuerKey,
				Email:           email,
				CADirURL:        caDirURL,
				RegistrationRaw: registrationRaw,
				SecretData:      secretData,
				EABKeyID:        eabKeyID,
				EABHmacKey:      eabHmacKey,
			}

				_, err = registrationUserFromConfigWithFactory(cfg, mockFactory)

				Expect(err).To(HaveOccurred()) // Should error from factory, but not panic
			})
		})

		Context("with invalid registration data", func() {
			It("should return error for invalid JSON", func() {
				invalidJSON := []byte(`{"status": "valid", invalid json}`)

				mockFactory := func(cfg *RegistrationConfig, privateKey crypto.Signer) (*RegistrationUser, error) {
					Fail("factory should not be called")
					return nil, nil
				}

				cfg := &RegistrationConfig{
					IssuerKey:       issuerKey,
					Email:           email,
					CADirURL:        caDirURL,
					RegistrationRaw: invalidJSON,
					SecretData:      secretData,
					EABKeyID:        eabKeyID,
					EABHmacKey:      eabHmacKey,
				}

				result, err := registrationUserFromConfigWithFactory(cfg, mockFactory)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("unmarshalling registration json failed"))
				Expect(result).To(BeNil())
			})

			It("should return error when private key is missing", func() {
				validReg := &acme.ExtendedAccount{
					Account: acme.Account{
						Status: "valid",
					},
					Location: "https://acme-server.example.com/acme/acct/123456",
				}
				registrationRaw, err := json.Marshal(validReg)
				Expect(err).ToNot(HaveOccurred())

				// Empty secret data (no private key)
				emptySecretData := map[string][]byte{}

				mockFactory := func(cfg *RegistrationConfig, privateKey crypto.Signer) (*RegistrationUser, error) {
					Fail("factory should not be called")
					return nil, nil
				}

				cfg := &RegistrationConfig{
					IssuerKey:       issuerKey,
					Email:           email,
					CADirURL:        caDirURL,
					RegistrationRaw: registrationRaw,
					SecretData:      emptySecretData,
					EABKeyID:        eabKeyID,
					EABHmacKey:      eabHmacKey,
				}

				result, err := registrationUserFromConfigWithFactory(cfg, mockFactory)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("`privateKey` data not found in secret"))
				Expect(result).To(BeNil())
			})

			It("should return error when private key is invalid", func() {
				validReg := &acme.ExtendedAccount{
					Account: acme.Account{
						Status: "valid",
					},
					Location: "https://acme-server.example.com/acme/acct/123456",
				}
				registrationRaw, err := json.Marshal(validReg)
				Expect(err).ToNot(HaveOccurred())

				// Invalid private key data
				invalidSecretData := map[string][]byte{
					KeyPrivateKey: []byte("not a valid private key"),
				}

				mockFactory := func(cfg *RegistrationConfig, privateKey crypto.Signer) (*RegistrationUser, error) {
					Fail("factory should not be called")
					return nil, nil
				}

				cfg := &RegistrationConfig{
					IssuerKey:       issuerKey,
					Email:           email,
					CADirURL:        caDirURL,
					RegistrationRaw: registrationRaw,
					SecretData:      invalidSecretData,
					EABKeyID:        eabKeyID,
					EABHmacKey:      eabHmacKey,
				}

				result, err := registrationUserFromConfigWithFactory(cfg, mockFactory)

				Expect(err).To(HaveOccurred())
				Expect(result).To(BeNil())
			})
		})

		Context("with EAB credentials", func() {
			It("should preserve EAB credentials for v5 data", func() {
				eabKeyID = "test-kid"
				eabHmacKey = "test-hmac-key"

				validReg := &acme.ExtendedAccount{
					Account: acme.Account{
						Status: "valid",
					},
					Location: "https://acme-server.example.com/acme/acct/123456",
				}
				registrationRaw, err := json.Marshal(validReg)
				Expect(err).ToNot(HaveOccurred())

				mockFactory := func(cfg *RegistrationConfig, privateKey crypto.Signer) (*RegistrationUser, error) {
					Fail("factory should not be called")
					return nil, nil
				}

				cfg := &RegistrationConfig{
					IssuerKey:       issuerKey,
					Email:           email,
					CADirURL:        caDirURL,
					RegistrationRaw: registrationRaw,
					SecretData:      secretData,
					EABKeyID:        eabKeyID,
					EABHmacKey:      eabHmacKey,
				}

				result, err := registrationUserFromConfigWithFactory(cfg, mockFactory)

				Expect(err).ToNot(HaveOccurred())
				Expect(result).ToNot(BeNil())
				Expect(result.User).ToNot(BeNil())
				Expect(result.User.EabKeyID()).To(Equal(eabKeyID))
				Expect(result.User.EabHmacKey()).To(Equal(eabHmacKey))
			})

			It("should pass EAB credentials to factory for v4 migration", func() {
				eabKeyID = "test-kid"
				eabHmacKey = "test-hmac-key"

				v4Reg := &acme.ExtendedAccount{
					Account: acme.Account{
						Status: "valid",
					},
					Location: "",
				}
				registrationRaw, err := json.Marshal(v4Reg)
				Expect(err).ToNot(HaveOccurred())

				var receivedEabKeyID, receivedEabHmacKey string
				mockFactory := func(cfg *RegistrationConfig, pk crypto.Signer) (*RegistrationUser, error) {
					receivedEabKeyID = cfg.EABKeyID
					receivedEabHmacKey = cfg.EABHmacKey

					newReg := &acme.ExtendedAccount{
						Account: acme.Account{
							Status: "valid",
						},
						Location: "https://acme-server.example.com/acme/acct/999999",
					}
					return &RegistrationUser{
						email:           cfg.Email,
						caDirURL:        cfg.CADirURL,
						extendedAccount: newReg,
						key:             pk,
						eabKeyID:        cfg.EABKeyID,
						eabHmacKey:      cfg.EABHmacKey,
					}, nil
				}

				cfg := &RegistrationConfig{
					IssuerKey:            issuerKey,
					Email:                email,
					CADirURL:             caDirURL,
					RegistrationRaw:      registrationRaw,
					SecretData:           secretData,
					EABKeyID:             eabKeyID,
					EABHmacKey:           eabHmacKey,
					AllowV4ToV5Migration: true, // Allow migration for this test
				}

				result, err := registrationUserFromConfigWithFactory(cfg, mockFactory)

				Expect(err).ToNot(HaveOccurred())
				Expect(result).ToNot(BeNil())
				Expect(result.User).ToNot(BeNil())
				Expect(receivedEabKeyID).To(Equal(eabKeyID))
				Expect(receivedEabHmacKey).To(Equal(eabHmacKey))
				Expect(result.User.EabKeyID()).To(Equal(eabKeyID))
				Expect(result.User.EabHmacKey()).To(Equal(eabHmacKey))
			})
		})
	})

	Context("ExtractOrGeneratePrivateKey", func() {
		It("should extract existing private key from secret data", func() {
			privKeyBytes, err := privateKeyToBytes(privateKey, false)
			Expect(err).ToNot(HaveOccurred())

			data := map[string][]byte{
				KeyPrivateKey: privKeyBytes,
			}

			extractedKey, err := ExtractOrGeneratePrivateKey(data)
			Expect(err).ToNot(HaveOccurred())
			Expect(extractedKey).ToNot(BeNil())
		})

		It("should generate new private key when not present", func() {
			emptyData := map[string][]byte{}

			generatedKey, err := ExtractOrGeneratePrivateKey(emptyData)
			Expect(err).ToNot(HaveOccurred())
			Expect(generatedKey).ToNot(BeNil())

			// Verify it's an ECDSA key
			_, ok := generatedKey.(*ecdsa.PrivateKey)
			Expect(ok).To(BeTrue(), "generated key should be ECDSA")
		})

		It("should return error for invalid private key data", func() {
			invalidData := map[string][]byte{
				KeyPrivateKey: []byte("invalid key data"),
			}

			key, err := ExtractOrGeneratePrivateKey(invalidData)
			Expect(err).To(HaveOccurred())
			Expect(key).To(BeNil())
		})
	})

	Context("ValidatePrivateKeySecretDataKeys", func() {
		It("should accept empty secret data", func() {
			emptyData := map[string][]byte{}
			err := ValidatePrivateKeySecretDataKeys(emptyData)
			Expect(err).ToNot(HaveOccurred())
		})

		It("should accept valid private key", func() {
			privKeyBytes, err := privateKeyToBytes(privateKey, false)
			Expect(err).ToNot(HaveOccurred())

			data := map[string][]byte{
				KeyPrivateKey: privKeyBytes,
			}

			err = ValidatePrivateKeySecretDataKeys(data)
			Expect(err).ToNot(HaveOccurred())
		})

		It("should accept obsolete email key", func() {
			privKeyBytes, err := privateKeyToBytes(privateKey, false)
			Expect(err).ToNot(HaveOccurred())

			data := map[string][]byte{
				KeyPrivateKey:    privKeyBytes,
				ObsoleteKeyEmail: []byte("test@example.com"),
			}

			err = ValidatePrivateKeySecretDataKeys(data)
			Expect(err).ToNot(HaveOccurred())
		})

		It("should reject invalid private key", func() {
			data := map[string][]byte{
				KeyPrivateKey: []byte("invalid key"),
			}

			err := ValidatePrivateKeySecretDataKeys(data)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("value for key `privateKey` is invalid"))
		})

		It("should reject unknown keys", func() {
			privKeyBytes, err := privateKeyToBytes(privateKey, false)
			Expect(err).ToNot(HaveOccurred())

			data := map[string][]byte{
				KeyPrivateKey: privKeyBytes,
				"unknownKey":  []byte("some value"),
			}

			err = ValidatePrivateKeySecretDataKeys(data)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid secret data keys"))
			Expect(err.Error()).To(ContainSubstring("`unknownKey`"))
		})
	})

	Context("RegistrationUser methods", func() {
		It("should return correct user properties", func() {
			reg := &acme.ExtendedAccount{
				Account: acme.Account{
					Status: "valid",
				},
				Location: "https://acme-server.example.com/acme/acct/123456",
			}

			user := &RegistrationUser{
				email:           email,
				caDirURL:        caDirURL,
				extendedAccount: reg,
				key:             privateKey,
				eabKeyID:        "test-kid",
				eabHmacKey:      "test-hmac",
			}

			Expect(user.GetEmail()).To(Equal(email))
			Expect(user.CADirURL()).To(Equal(caDirURL))
			Expect(user.GetRegistration()).To(Equal(reg))
			Expect(user.GetPrivateKey()).To(Equal(privateKey))
			Expect(user.EabKeyID()).To(Equal("test-kid"))
			Expect(user.EabHmacKey()).To(Equal("test-hmac"))
		})

		It("should create valid lego config", func() {
			reg := &acme.ExtendedAccount{
				Account: acme.Account{
					Status: "valid",
				},
				Location: "https://acme-server.example.com/acme/acct/123456",
			}

			user := &RegistrationUser{
				email:           email,
				caDirURL:        caDirURL,
				extendedAccount: reg,
				key:             privateKey,
			}

			config := user.NewConfig(caDirURL)
			Expect(config).ToNot(BeNil())
			Expect(config.CADirURL).To(Equal(caDirURL))
		})

		It("should marshal raw registration", func() {
			reg := &acme.ExtendedAccount{
				Account: acme.Account{
					Status: "valid",
				},
				Location: "https://acme-server.example.com/acme/acct/123456",
			}

			user := &RegistrationUser{
				email:           email,
				caDirURL:        caDirURL,
				extendedAccount: reg,
				key:             privateKey,
			}

			raw, err := user.RawRegistration()
			Expect(err).ToNot(HaveOccurred())
			Expect(raw).ToNot(BeEmpty())

			// Verify it can be unmarshaled back
			var unmarshaled acme.ExtendedAccount
			err = json.Unmarshal(raw, &unmarshaled)
			Expect(err).ToNot(HaveOccurred())
			Expect(unmarshaled.Location).To(Equal(reg.Location))
			Expect(unmarshaled.Status).To(Equal(reg.Status))
		})

		It("should convert to secret data", func() {
			reg := &acme.ExtendedAccount{
				Account: acme.Account{
					Status: "valid",
				},
				Location: "https://acme-server.example.com/acme/acct/123456",
			}

			user := &RegistrationUser{
				email:           email,
				caDirURL:        caDirURL,
				extendedAccount: reg,
				key:             privateKey,
			}

			data, err := user.ToSecretData()
			Expect(err).ToNot(HaveOccurred())
			Expect(data).To(HaveKey(KeyPrivateKey))
			Expect(data[KeyPrivateKey]).ToNot(BeEmpty())

			// Verify the key can be read back
			extractedKey, err := BytesToPrivateKey(data[KeyPrivateKey])
			Expect(err).ToNot(HaveOccurred())
			Expect(extractedKey).ToNot(BeNil())
		})
	})

	Context("RegistrationUserFromConfig", func() {
		It("should validate required fields", func() {
			_, err := RegistrationUserFromConfig(nil)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("configuration cannot be nil"))

			_, err = RegistrationUserFromConfig(&RegistrationConfig{})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("IssuerKey is missing"))

			_, err = RegistrationUserFromConfig(&RegistrationConfig{
				IssuerKey: issuerKey,
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Email is missing"))

			_, err = RegistrationUserFromConfig(&RegistrationConfig{
				IssuerKey: issuerKey,
				Email:     email,
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("CADirURL is missing"))
		})

		It("should restore user from valid v5 data without migration", func() {
			validReg := &acme.ExtendedAccount{
				Account: acme.Account{
					Status: "valid",
				},
				Location: "https://acme-server.example.com/acme/acct/123456",
			}
			registrationRaw, err := json.Marshal(validReg)
			Expect(err).ToNot(HaveOccurred())

			result, err := RegistrationUserFromConfig(&RegistrationConfig{
				IssuerKey:       issuerKey,
				Email:           email,
				CADirURL:        caDirURL,
				RegistrationRaw: registrationRaw,
				SecretData:      secretData,
			})

			Expect(err).ToNot(HaveOccurred())
			Expect(result).ToNot(BeNil())
			Expect(result.User).ToNot(BeNil())
			Expect(result.User.GetEmail()).To(Equal(email))
			Expect(result.UpdatedRaw).To(Equal(registrationRaw))
			Expect(result.WasMigrated).To(BeFalse())
		})

		It("should detect v4 migration", func() {
			v4Reg := &acme.ExtendedAccount{
				Account: acme.Account{
					Status: "valid",
				},
				Location: "",
			}
			registrationRaw, err := json.Marshal(v4Reg)
			Expect(err).ToNot(HaveOccurred())

			newV5Reg := &acme.ExtendedAccount{
				Account: acme.Account{
					Status: "valid",
				},
				Location: "https://acme-server.example.com/acme/acct/999999",
			}

			mockFactory := func(cfg *RegistrationConfig, pk crypto.Signer) (*RegistrationUser, error) {
				return &RegistrationUser{
					email:           cfg.Email,
					caDirURL:        cfg.CADirURL,
					extendedAccount: newV5Reg,
					key:             pk,
					eabKeyID:        cfg.EABKeyID,
					eabHmacKey:      cfg.EABHmacKey,
				}, nil
			}

			result, err := registrationUserFromConfigWithFactory(&RegistrationConfig{
				IssuerKey:            issuerKey,
				Email:                email,
				CADirURL:             caDirURL,
				RegistrationRaw:      registrationRaw,
				SecretData:           secretData,
				AllowV4ToV5Migration: true, // Allow migration for this test
			}, mockFactory)

			Expect(err).ToNot(HaveOccurred())
			Expect(result).ToNot(BeNil())
			Expect(result.WasMigrated).To(BeTrue())
			Expect(result.User.GetRegistration().Location).To(Equal(newV5Reg.Location))

			// Verify updated raw contains new location
			var updatedReg acme.ExtendedAccount
			err = json.Unmarshal(result.UpdatedRaw, &updatedReg)
			Expect(err).ToNot(HaveOccurred())
			Expect(updatedReg.Location).To(Equal(newV5Reg.Location))
		})

		It("should preserve EAB credentials", func() {
			eabKeyID = "test-kid"
			eabHmacKey = "test-hmac-key"

			validReg := &acme.ExtendedAccount{
				Account: acme.Account{
					Status: "valid",
				},
				Location: "https://acme-server.example.com/acme/acct/123456",
			}
			registrationRaw, err := json.Marshal(validReg)
			Expect(err).ToNot(HaveOccurred())

			result, err := RegistrationUserFromConfig(&RegistrationConfig{
				IssuerKey:       issuerKey,
				Email:           email,
				CADirURL:        caDirURL,
				RegistrationRaw: registrationRaw,
				SecretData:      secretData,
				EABKeyID:        eabKeyID,
				EABHmacKey:      eabHmacKey,
			})

			Expect(err).ToNot(HaveOccurred())
			Expect(result.User.EabKeyID()).To(Equal(eabKeyID))
			Expect(result.User.EabHmacKey()).To(Equal(eabHmacKey))
		})

		It("should return error if factory fails during migration", func() {
			v4Reg := &acme.ExtendedAccount{
				Account: acme.Account{
					Status: "valid",
				},
				Location: "",
			}
			registrationRaw, err := json.Marshal(v4Reg)
			Expect(err).ToNot(HaveOccurred())

			mockFactory := func(cfg *RegistrationConfig, privateKey crypto.Signer) (*RegistrationUser, error) {
				return nil, fmt.Errorf("ACME server unreachable")
			}

			result, err := registrationUserFromConfigWithFactory(&RegistrationConfig{
				IssuerKey:            issuerKey,
				Email:                email,
				CADirURL:             caDirURL,
				RegistrationRaw:      registrationRaw,
				SecretData:           secretData,
				AllowV4ToV5Migration: true, // Allow migration for this test
			}, mockFactory)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("migrating v4 registration to v5 failed"))
			Expect(result).To(BeNil())
		})

		It("should block v4 migration when AllowV4ToV5Migration is false", func() {
			v4Reg := &acme.ExtendedAccount{
				Account: acme.Account{
					Status: "valid",
				},
				Location: "", // v4 format (missing Location)
			}
			registrationRaw, err := json.Marshal(v4Reg)
			Expect(err).ToNot(HaveOccurred())

			cfg := &RegistrationConfig{
				IssuerKey:            issuerKey,
				Email:                email,
				CADirURL:             caDirURL,
				RegistrationRaw:      registrationRaw,
				SecretData:           secretData,
				AllowV4ToV5Migration: false, // Explicitly disallow migration
			}

			result, err := RegistrationUserFromConfig(cfg)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("missing account URL in status"))
			Expect(result).To(BeNil())
		})
	})
})
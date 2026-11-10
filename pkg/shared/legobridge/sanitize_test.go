/*
 * SPDX-FileCopyrightText: Contributors to the Gardener project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package legobridge

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("SanitizeACMEError", func() {
	It("strips the server-controlled Detail from an ACME ProblemDetails", func() {
		pd := &acme.ProblemDetails{
			HTTPStatus: 403,
			Type:       "urn:ietf:params:acme:error:unauthorized",
			Detail:     "secret-internal-response-body",
		}
		msg, ok := SanitizeACMEError(fmt.Errorf("obtaining certificate failed: %w", pd))
		Expect(ok).To(BeTrue())
		Expect(msg).To(HavePrefix("acme: error: 403 :: urn:ietf:params:acme:error:unauthorized"))
		Expect(msg).NotTo(ContainSubstring("secret-internal-response-body"))
	})

	It("omits the raw response body that lego echoes on an unmarshalling failure", func() {
		// mirrors lego's UnmarshalError.Error() format
		leak := fmt.Errorf("get directory at 'http://169.254.169.254/': unable to unmarshal response: [status code: 200] body: {internal-metadata-token} error: invalid character")
		msg, ok := SanitizeACMEError(fmt.Errorf("creating registration user failed: %w", leak))
		Expect(ok).To(BeTrue())
		Expect(msg).NotTo(ContainSubstring("internal-metadata-token"))
		Expect(msg).To(HavePrefix("creating registration user failed: get directory at 'http://169.254.169.254/': unable to unmarshal response: [status code: 200]"))
	})

	It("preserves a client-side input error such as a malformed EAB key", func() {
		err := fmt.Errorf("creating registration user failed: %w",
			fmt.Errorf("acme: could not decode hmac key: illegal base64 data at input byte 0"))
		msg, ok := SanitizeACMEError(err)
		Expect(ok).To(BeFalse())
		Expect(msg).To(Equal("creating registration user failed: acme: could not decode hmac key: illegal base64 data at input byte 0"))
	})

	It("passes a non-ACME error through unchanged", func() {
		msg, ok := SanitizeACMEError(fmt.Errorf("loading issuer secret failed"))
		Expect(ok).To(BeFalse())
		Expect(msg).To(Equal("loading issuer secret failed"))
	})

	// Guards the coupling to lego's internal UnmarshalError format: it drives the real lego directory
	// fetch against a server that echoes a secret in a non-JSON body. If a lego bump changes the
	// " body: " format the acmeBodyMarker relies on, this test fails instead of silently re-exposing
	// the response body in the CR status.
	It("strips the response body from the real error lego returns for a non-JSON ACME directory", func() {
		const secret = "internal-metadata-token-should-not-leak"
		// lego requires HTTPS for the ACME server, so use a TLS test server and its trusting client.
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("not-json " + secret))
		}))
		defer server.Close()

		privateKey, err := ExtractOrGeneratePrivateKey(nil)
		Expect(err).NotTo(HaveOccurred())
		user := &RegistrationUser{email: "test@example.com", key: privateKey, caDirURL: server.URL}
		config := user.NewConfig(server.URL)
		config.HTTPClient = server.Client()

		client, err := lego.NewClient(config)
		if err == nil {
			_, err = client.Registration.Register(context.Background(), registration.RegisterOptions{TermsOfServiceAgreed: true})
		}
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(secret), "precondition: lego is expected to echo the body")

		msg, ok := SanitizeACMEError(err)
		Expect(ok).To(BeTrue())
		Expect(msg).NotTo(ContainSubstring(secret))
	})
})

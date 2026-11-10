/*
 * SPDX-FileCopyrightText: Contributors to the Gardener project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package legobridge

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-acme/lego/v5/acme"
)

// acmeBodyMarker is the substring lego's UnmarshalError uses right before echoing the raw response
// body ("... body: <raw body>"). The ACME server URL is user-supplied, so that body is attacker
// controlled and must not be exposed in a CR status.
const acmeBodyMarker = " body: "

// SanitizeACMEError returns a message safe to write into a CR status.message and whether err carried
// ACME-server-controlled content. The ACME server URL is user-supplied; the Detail of a
// ProblemDetails and the raw response body echoed by lego on an unmarshalling failure are an
// information-disclosure risk and must not be exposed in the status. Other error text (including
// client-side input validation such as a malformed EAB key) is preserved. Callers should log the
// full err themselves when ok is true.
func SanitizeACMEError(err error) (safeMsg string, ok bool) {
	var pd *acme.ProblemDetails
	if errors.As(err, &pd) {
		return fmt.Sprintf("acme: error: %d :: %s (see controller logs for details)", pd.HTTPStatus, pd.Type), true
	}

	msg := err.Error()
	if i := strings.Index(msg, acmeBodyMarker); i >= 0 {
		return msg[:i] + " (response body omitted, see controller logs for details)", true
	}

	return msg, false
}

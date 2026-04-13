/*
 * SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package shared

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ParseRenewBefore parses the renewBefore duration string and returns a *metav1.Duration and an optional error.
// Returns (nil, error) if the string is invalid or the duration is less than 5 minutes.
// Returns (nil, nil) if the string is empty.
// The default of 30 days is applied by the certificate controller if nil is returned.
func ParseRenewBefore(renewBeforeStr string) (*metav1.Duration, error) {
	if renewBeforeStr == "" {
		return nil, nil
	}

	duration, err := time.ParseDuration(renewBeforeStr)
	if err != nil {
		return nil, fmt.Errorf("invalid renew-before annotation value %q: %w", renewBeforeStr, err)
	}

	// Validate minimum of 5 minutes
	if duration < 5*time.Minute {
		return nil, fmt.Errorf("invalid renew-before annotation value %q: must be at least 5 minutes", renewBeforeStr)
	}

	return &metav1.Duration{Duration: duration}, nil
}

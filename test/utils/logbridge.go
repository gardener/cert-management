// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package testutils

import (
	"log"
	"strings"

	"github.com/go-logr/logr"
)

type logBridge struct {
	logr logr.Logger
}

func (logBridge *logBridge) Write(p []byte) (n int, err error) {
	message := strings.TrimSpace(string(p))

	logBridge.logr.Info(message)

	return len(p), nil
}

// NewLogBridge creates a new log.Logger that forwards all log messages to the given logr.Logger.
func NewLogBridge(logr logr.Logger) *log.Logger {
	writer := &logBridge{logr}

	return log.New(writer, "", 0)
}

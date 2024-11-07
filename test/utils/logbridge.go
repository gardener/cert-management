package testutils

import (
	"github.com/go-logr/logr"
	"log"
	"strings"
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

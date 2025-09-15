package logging

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestLogging(t *testing.T) {
	// Test basic logging functions
	Debugf("Debug message")
	Infof("Info message")
	Warnf("Warning message")
	Errorf("Error message")

	// No assertion needed, just making sure it doesn't panic
	assert.True(t, true)
}

func TestSetLevel(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	originalOutput := logger.Out
	logger.SetOutput(&buf)
	defer logger.SetOutput(originalOutput)

	// Set level to Info
	SetLevel(InfoLevel)

	// Debug should not be logged
	Debugf("Debug message")
	assert.Empty(t, buf.String())

	// Info should be logged
	buf.Reset()
	Infof("Info message")
	assert.Contains(t, buf.String(), "Info message")
}

func TestWithFields(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	originalOutput := logger.Out
	logger.SetOutput(&buf)
	defer logger.SetOutput(originalOutput)

	// Set level to Debug to capture all logs
	SetLevel(DebugLevel)

	// Log with fields
	fields := logrus.Fields{
		"component": "test",
		"id":        123,
	}

	InfoWithFields(fields, "Message with fields")

	// Check that fields are in the log
	logOutput := buf.String()
	assert.Contains(t, logOutput, "Message with fields")
	assert.Contains(t, logOutput, "component=test")
	assert.Contains(t, logOutput, "id=123")
}

func TestFileLogging(t *testing.T) {
	// Create temporary directory for logs
	tempDir, err := os.MkdirTemp("", "logging_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Enable file logging
	err = EnableFileLogging(tempDir, "test.log", 10, 3, 7)
	assert.NoError(t, err)

	// Log some messages
	Infof("File log test message")

	// Check that log file was created
	logFile := filepath.Join(tempDir, "test.log")
	_, err = os.Stat(logFile)
	assert.NoError(t, err)

	// Check log content
	content, err := os.ReadFile(logFile)
	assert.NoError(t, err)
	assert.Contains(t, string(content), "File log test message")

	// Reset logger output to stdout
	logger.SetOutput(os.Stdout)
}

func TestSetFormatter(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	originalOutput := logger.Out
	logger.SetOutput(&buf)
	defer logger.SetOutput(originalOutput)

	// Set JSON formatter
	SetFormatter(&logrus.JSONFormatter{})

	// Log a message
	Infof("JSON formatted message")

	// Check that output is JSON
	logOutput := buf.String()
	assert.Contains(t, logOutput, "\"level\":\"info\"")
	assert.Contains(t, logOutput, "\"msg\":\"JSON formatted message\"")

	// Reset formatter
	SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
}

func TestSetOutput(t *testing.T) {
	// Create a custom writer
	var buf bytes.Buffer

	// Set output to our buffer
	SetOutput(&buf)

	// Log a message
	Infof("Custom output message")

	// Check that message went to our buffer
	assert.Contains(t, buf.String(), "Custom output message")

	// Reset output to stdout
	SetOutput(os.Stdout)
}

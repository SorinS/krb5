// Package test provides useful resources for the testing of krb5.
package test

import (
	"os"
	"strings"
	"testing"
)

// Test enabling environment variable key values.
const (
	IntegrationEnvVar     = "INTEGRATION"
	ADIntegrationEnvVar   = "TESTAD"
	PrivIntegrationEnvVar = "TESTPRIVILEGED"
)

// Integration skips the test unless the integration test environment variable is set.
func Integration(t *testing.T) {
	if os.Getenv(IntegrationEnvVar) != "1" {
		t.Skip("Skipping integration test")
	}
}

// AD skips the test unless the AD test environment variable is set.
func AD(t *testing.T) {
	if os.Getenv(ADIntegrationEnvVar) != "1" {
		t.Skip("Skipping AD integration test")
	}
}

// Privileged skips the test that require local root privilege.
func Privileged(t *testing.T) {
	if os.Getenv(PrivIntegrationEnvVar) != "1" {
		t.Skip("Skipping DNS integration test")
	}
}

// MITDirEnvVar names the directory test/mitkdc/mitkdc.py keeps its KDCs'
// files in (krb5.conf, svc.keytab, krbtgt.keytab).
const MITDirEnvVar = "TEST_MIT_DIR"

// MIT skips the test unless the integration test environment variable is
// set and test/mitkdc/mitkdc.py's KDCs are running; it returns their
// directory.
func MIT(t *testing.T) string {
	t.Helper()
	Integration(t)

	dir := os.Getenv(MITDirEnvVar)
	if dir == "" {
		t.Skip("Skipping MIT KDC test: " + MITDirEnvVar + " is not set (see test/README.md)")
	}

	return dir
}

// Capture reports whether TEST_CAPTURE=1: integration tests then log what
// they saw (tickets, keys) for the unit tests' vectors.
func Capture() bool {
	return os.Getenv("TEST_CAPTURE") == "1"
}

// ADDirEnvVar names a directory with what the live AD tests need: a
// krb5.conf for the domain GOOSE.TEST (its KDC reached on loopback, see
// test/README.md), the service's keytab web.keytab (HTTP/web.goose.test),
// and ADPasswordFileEnvVar a file with the test users' password.
const (
	ADDirEnvVar          = "TEST_AD_DIR"
	ADPasswordFileEnvVar = "TEST_AD_PASSWORD_FILE"
)

// ADLive skips the test unless the integration test environment variable
// is set and TEST_AD_DIR and TEST_AD_PASSWORD_FILE are (TESTAD is for the
// older tests' AD, TEST.GOKRB5); it returns the directory and the users'
// password.
func ADLive(t *testing.T) (string, string) {
	t.Helper()
	Integration(t)

	dir, pwFile := os.Getenv(ADDirEnvVar), os.Getenv(ADPasswordFileEnvVar)
	if dir == "" || pwFile == "" {
		t.Skip("Skipping live AD test: " + ADDirEnvVar + " or " + ADPasswordFileEnvVar + " is not set (see test/README.md)")
	}

	b, err := os.ReadFile(pwFile)
	if err != nil {
		t.Fatalf("reading the AD password file: %v", err)
	}

	return dir, strings.TrimSpace(string(b))
}

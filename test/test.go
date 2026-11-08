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
// krb5.conf whose default_realm is the domain's realm (GOOSE.TEST in
// test/ad/README.md, its KDC reached on loopback), the service's keytab
// web.keytab (HTTP/web.<domain>), and ADPasswordFileEnvVar a file with the
// test users' password.
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
		t.Skip("Skipping live AD test: " + ADDirEnvVar + " or " + ADPasswordFileEnvVar + " is not set (see test/ad/README.md)")
	}

	b, err := os.ReadFile(pwFile)
	if err != nil {
		t.Fatalf("reading the AD password file: %v", err)
	}

	return dir, strings.TrimSpace(string(b))
}

// ADDomain returns the live AD's realm, the krb5.conf's default realm given,
// and its DNS domain, the realm in lower case, which the test accounts' SPNs
// are under (HTTP/web.<domain>). Without a default realm the test fails.
func ADDomain(t *testing.T, defaultRealm string) (string, string) {
	t.Helper()

	if defaultRealm == "" {
		t.Fatal("the live AD's krb5.conf has no default_realm: it is the domain's realm")
	}

	return defaultRealm, strings.ToLower(defaultRealm)
}

// ADPeerRealmEnvVar names a second AD forest's realm, trusted both ways by
// the one TEST_AD_DIR's krb5.conf has as its default realm (that krb5.conf
// lists both realms and maps both domains), with its own alice and bob.
const ADPeerRealmEnvVar = "TEST_AD_PEER_REALM"

// ADPeerRealm skips the test unless ADLive would not and TEST_AD_PEER_REALM
// is set; it returns the directory, the users' password and the peer realm.
func ADPeerRealm(t *testing.T) (string, string, string) {
	t.Helper()

	dir, password := ADLive(t)

	peer := os.Getenv(ADPeerRealmEnvVar)
	if peer == "" {
		t.Skip("Skipping cross-realm AD test: " + ADPeerRealmEnvVar + " is not set (see test/ad/README.md)")
	}

	return dir, password, peer
}

// MITBin returns the directory of MIT's tools (kinit, klist, kvno) that
// test/mitkdc/mitkdc.py found, skipping the test without it.
func MITBin(t *testing.T) string {
	t.Helper()

	bin := os.Getenv("TEST_MIT_BIN")
	if bin == "" {
		t.Skip("Skipping: TEST_MIT_BIN is not set (see test/README.md)")
	}

	return bin
}

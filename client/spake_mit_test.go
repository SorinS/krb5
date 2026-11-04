package client_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/spake"
	"github.com/go-krb5/krb5/test"
)

// mitConfigGroups is the MIT test krb5.conf with spake_preauth_groups set.
func mitConfigGroups(t *testing.T, dir, groups string) *config.Config {
	t.Helper()

	conf, err := os.ReadFile(filepath.Join(dir, "krb5.conf"))
	require.NoError(t, err)

	s := string(conf)
	if groups != "" {
		s = strings.Replace(s, "[libdefaults]", "[libdefaults]\n    spake_preauth_groups = "+groups, 1)
	}

	cfg, err := config.NewFromString(s)
	require.NoError(t, err)

	return cfg
}

// spakeUsed reports whether the requests a dialer saw carried PA-SPAKE.
func spakeUsed(t *testing.T, rec *recordingDialer) bool {
	t.Helper()

	for _, b := range rec.sent() {
		if b[0] != 0x6a {
			continue
		}

		var r messages.ASReq
		require.NoError(t, r.Unmarshal(b))

		if r.PAData.Contains(patype.PA_SPAKE) {
			return true
		}
	}

	return false
}

// S.TEST's KDC offers SPAKE in all four groups and no encrypted timestamp:
// a password works only through SPAKE (or FAST). sam logs in with each
// group; sam-ETYPE with each encryption type (K'[0] is of the initial
// key's type).
func TestClient_SPAKE_MIT(t *testing.T) {
	dir := test.MIT(t)

	for _, g := range []string{"edwards25519", "P-256", "P-384", "P-521"} {
		rec := &recordingDialer{}
		cl := client.NewWithPassword("sam", "S.TEST", "sam-pw", mitConfigGroups(t, dir, g), client.UseDialer(rec))
		require.NoError(t, cl.Login(), g)
		assert.True(t, spakeUsed(t, rec), g)
	}

	cfg := mitConfigGroups(t, dir, "")
	for _, e := range []string{"aes128", "aes256", "sha2-128", "sha2-256", "rc4", "cam128", "cam256"} {
		name := "sam-" + e
		cl := client.NewWithPassword(name, "S.TEST", name+"-pw", cfg)
		require.NoError(t, cl.Login(), name)

		_, _, err := cl.GetServiceTicket("host/fast.s.test")
		require.NoError(t, err, name)
	}

	// A wrong password: the KDC cannot decrypt our factor.
	cl := client.NewWithPassword("sam", "S.TEST", "wrong", cfg)
	err := cl.Login()
	require.Error(t, err)

	var kerr messages.KRBError
	require.True(t, errors.As(err, &kerr), "%v", err)
	assert.Equal(t, errorcode.KDC_ERR_PREAUTH_FAILED, kerr.ErrorCode)

	// SPAKE inside FAST, armored by host/fast.s.test's TGT.
	armor, err := fastHost(t, dir, cfg, "s-fast.keytab", "S.TEST").Armor()
	require.NoError(t, err)

	rec := &recordingDialer{}
	cl = client.NewWithPassword("sam", "S.TEST", "sam-pw", mitConfigGroups(t, dir, "P-256"), client.FASTArmor(armor), client.UseDialer(rec))
	require.NoError(t, cl.Login())

	for _, b := range rec.sent() {
		if b[0] == 0x6a {
			var r messages.ASReq
			require.NoError(t, r.Unmarshal(b))
			assert.False(t, r.PAData.Contains(patype.PA_SPAKE), "PA-SPAKE outside the armor")
		}
	}
}

// O.TEST's KDC sends an optimistic edwards25519 challenge in its first
// error and takes edwards25519 and P-256 only (and encrypted timestamp).
func TestClient_SPAKE_Optimistic_MIT(t *testing.T) {
	dir := test.MIT(t)

	// edwards25519: the optimistic challenge answered at once.
	rec := &recordingDialer{}
	cl := client.NewWithPassword("olga", "O.TEST", "olga-pw", mitConfigGroups(t, dir, ""), client.UseDialer(rec))
	require.NoError(t, cl.Login())
	assert.True(t, spakeUsed(t, rec))

	var supports int

	for _, b := range rec.sent() {
		var r messages.ASReq
		if b[0] != 0x6a || r.Unmarshal(b) != nil {
			continue
		}

		for _, pa := range r.PAData {
			var m spake.Message
			if pa.PADataType == patype.PA_SPAKE && m.Unmarshal(pa.PADataValue) == nil && m.Choice == spake.ChoiceSupport {
				supports++
			}
		}
	}

	assert.Zero(t, supports, "no support message for a challenge in a group we take")

	// P-256: the challenge refused, our groups sent, the KDC's P-256
	// challenge answered.
	cl = client.NewWithPassword("olga", "O.TEST", "olga-pw", mitConfigGroups(t, dir, "P-256"))
	require.NoError(t, cl.Login())

	// P-384, which O.TEST does not take: the encrypted timestamp instead.
	rec = &recordingDialer{}
	cl = client.NewWithPassword("olga", "O.TEST", "olga-pw", mitConfigGroups(t, dir, "P-384"), client.UseDialer(rec))
	require.NoError(t, cl.Login())

	var timestamp bool

	for _, b := range rec.sent() {
		var r messages.ASReq
		if b[0] == 0x6a && r.Unmarshal(b) == nil && r.PAData.Contains(patype.PA_ENC_TIMESTAMP) {
			timestamp = true
		}
	}

	assert.True(t, timestamp)
}

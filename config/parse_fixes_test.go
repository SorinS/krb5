package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana/etypeID"
)

// What MIT takes and this parser did not (upstream PR 448, CL 523, issues
// 504, 518, 526).
func TestParseFixes(t *testing.T) {
	t.Parallel()

	c, err := NewFromString(`[libdefaults]
    default_realm = A.TEST
    dns_canonicalize_hostname = fallback
    default_tkt_enctypes = AES256-CTS AES128-CTS RC4-HMAC
    default_tgs_enctypes = aes camellia -aes128-sha2
    permitted_enctypes = DEFAULT -rc4
[realms]
    ATHENA.MIT.EDU = { kdc = kerberos.mit.edu }
    A.TEST = { kdc = a1.a.test
        kdc = a2.a.test
        auth_to_local = RULE:[1:$1@$0](.*@A=B)s/@.*//
        admin_server = admin.a.test }
    B.TEST = {
        kdc = b.b.test
        v4_instance_convert = {
            mit = mit.edu
        }
    }
[domain_realm]
    .a.test = A.TEST
`)
	require.Error(t, err, "v4_instance_convert is reported as unsupported")
	require.IsType(t, UnsupportedDirective{}, err)

	assert.False(t, c.LibDefaults.DNSCanonicalizeHostname)
	assert.True(t, c.LibDefaults.DNSCanonicalizeHostnameFallback)

	assert.Equal(t, []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.RC4_HMAC},
		c.LibDefaults.DefaultTktEnctypeIDs)
	assert.Equal(t, []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96,
		etypeID.AES256_CTS_HMAC_SHA384_192, etypeID.CAMELLIA256_CTS_CMAC, etypeID.CAMELLIA128_CTS_CMAC},
		c.LibDefaults.DefaultTGSEnctypeIDs)
	assert.NotContains(t, c.LibDefaults.PermittedEnctypeIDs, etypeID.RC4_HMAC)
	assert.Contains(t, c.LibDefaults.PermittedEnctypeIDs, etypeID.AES256_CTS_HMAC_SHA1_96)

	require.Len(t, c.Realms, 3)
	assert.Equal(t, "ATHENA.MIT.EDU", c.Realms[0].Realm)
	assert.Equal(t, []string{"kerberos.mit.edu:88"}, c.Realms[0].KDC)
	assert.Equal(t, []string{"a1.a.test:88", "a2.a.test:88"}, c.Realms[1].KDC, "the KDC on the { line too")
	assert.Equal(t, []string{"admin.a.test"}, c.Realms[1].AdminServer, "the line with the }")
	assert.Equal(t, []string{"b.b.test:88"}, c.Realms[2].KDC)

	for _, bad := range []string{"[realms]\n A = { kdc = x\n", "[realms]\n A = { kdc = x } junk\n", "[realms]\n }\n"} {
		_, err := NewFromString(bad)
		assert.Error(t, err, bad)
	}
}

func TestLoad_Includes(t *testing.T) {
	t.Parallel()

	d := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(d, "krb5.conf.d"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(d, "krb5.conf.d", "crypto-policies"), []byte("[libdefaults]\n permitted_enctypes = aes256-cts\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(d, "krb5.conf.d", "realm.conf"), []byte("[realms]\n B.TEST = {\n  kdc = b.test\n }\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(d, "krb5.conf.d", "skipped.rpmnew"), []byte("[realms]\n C.TEST = {\n  kdc = c.test\n }\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(d, "extra"), []byte("[domain_realm]\n .b.test = B.TEST\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(d, "krb5.conf"), []byte("includedir "+filepath.Join(d, "krb5.conf.d")+
		"\ninclude "+filepath.Join(d, "extra")+"\n[libdefaults]\n default_realm = B.TEST\n"), 0o600))

	c, err := Load(filepath.Join(d, "krb5.conf"))
	require.NoError(t, err)
	assert.Equal(t, "B.TEST", c.LibDefaults.DefaultRealm)
	assert.Equal(t, []int32{etypeID.AES256_CTS_HMAC_SHA1_96}, c.LibDefaults.PermittedEnctypeIDs)
	require.Len(t, c.Realms, 1, "the .rpmnew file is not read")
	assert.Equal(t, "B.TEST", c.ResolveRealm("x.b.test"))

	// An include of itself stops.
	require.NoError(t, os.WriteFile(filepath.Join(d, "loop"), []byte("include "+filepath.Join(d, "loop")+"\n"), 0o600))
	_, err = Load(filepath.Join(d, "loop"))
	assert.Error(t, err)
}

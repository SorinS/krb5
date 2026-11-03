package credentials

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

// A cache read and written again is the same bytes: go-krb5's vector (a
// version 4 cache with a KDC offset and a configuration entry) and one MIT
// 1.22's kinit and kvno made.
func TestCCache_MarshalRoundTrip(t *testing.T) {
	t.Parallel()

	for name, v := range map[string]string{"CCACHE_TEST": testdata.CCACHE_TEST, "CCACHE_MIT_1_22": testdata.CCACHE_MIT_1_22} {
		b, err := hex.DecodeString(v)
		require.NoError(t, err)

		var c CCache
		require.NoError(t, c.Unmarshal(b), name)

		out, err := c.Marshal()
		require.NoError(t, err)
		assert.Equal(t, b, out, name)
	}
}

func TestCCache_MIT(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.CCACHE_MIT_1_22)
	require.NoError(t, err)

	var c CCache
	require.NoError(t, c.Unmarshal(b))

	assert.Equal(t, "bob", c.DefaultPrincipal.PrincipalName.PrincipalNameString())
	assert.Len(t, c.GetEntries(), 2)

	v, ok := c.Config("fast_avail", "krbtgt/A.TEST@A.TEST")
	assert.True(t, ok)
	assert.Equal(t, "yes", string(v))

	v, ok = c.Config("pa_type", "krbtgt/A.TEST@A.TEST")
	assert.True(t, ok)
	assert.Equal(t, "2", string(v))

	_, ok = c.Config("refresh_time", "")
	assert.False(t, ok)

	d, ok := c.KDCOffset()
	assert.False(t, ok)
	assert.Equal(t, time.Duration(0), d)

	tgt, ok := c.GetEntry(types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/A.TEST"))
	require.True(t, ok)
	assert.Equal(t, int32(18), tgt.Key.KeyType)
	assert.True(t, tgt.EndTime.After(tgt.AuthTime))
}

// Every prefix of a cache, and every changed byte, is read without a panic
// (upstream issue 519): a prefix that ends inside a credential is refused.
func TestCCache_Malformed(t *testing.T) {
	t.Parallel()

	for _, v := range []string{testdata.CCACHE_TEST, testdata.CCACHE_MIT_1_22} {
		b, err := hex.DecodeString(v)
		require.NoError(t, err)

		for n := 0; n < len(b); n++ {
			var c CCache
			_ = c.Unmarshal(b[:n])
		}

		for i := range b {
			changed := append([]byte(nil), b...)
			changed[i] ^= 0xff

			var c CCache
			_ = c.Unmarshal(changed)
		}

		var c CCache
		assert.Error(t, c.Unmarshal(b[:len(b)-1]))
	}

	// A huge realm length.
	var c CCache
	assert.Error(t, c.Unmarshal([]byte{5, 4, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0x7f, 0xff, 0xff, 0xff}))
}

func FuzzCCacheUnmarshal(f *testing.F) {
	for _, v := range []string{testdata.CCACHE_TEST, testdata.CCACHE_MIT_1_22} {
		b, _ := hex.DecodeString(v)
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		var c CCache
		if c.Unmarshal(b) != nil {
			return
		}

		// What reads, writes; what it writes reads back the same.
		out, err := c.Marshal()
		if err != nil {
			return
		}

		var d CCache
		require.NoError(t, d.Unmarshal(out))

		again, err := d.Marshal()
		require.NoError(t, err)
		assert.Equal(t, out, again)
	})
}

// A new cache: the KDC offset, configuration entries, credentials replaced
// for the same server, saved with mode 0600 and read back.
func TestCCache_NewSave(t *testing.T) {
	t.Parallel()

	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	c := NewV4CCache(cname, "A.TEST")
	c.SetKDCOffset(-1500*time.Millisecond + 900*time.Second)
	c.SetConfig("fast_avail", "krbtgt/A.TEST@A.TEST", []byte("yes"))

	now := time.Unix(1762207200, 0)
	cred := &Credential{
		Client:      Principal{Realm: "A.TEST", PrincipalName: cname},
		Server:      Principal{Realm: "A.TEST", PrincipalName: types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/A.TEST")},
		Key:         types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)},
		AuthTime:    now,
		StartTime:   now,
		EndTime:     now.Add(10 * time.Hour),
		RenewTill:   time.Unix(1<<31+5, 0), // past 2038
		TicketFlags: types.NewKrbFlags(),
		Ticket:      []byte{0x61, 0x00},
	}
	c.AddCredential(cred)

	newer := *cred
	newer.EndTime = now.Add(11 * time.Hour)
	c.AddCredential(&newer)
	require.Len(t, c.Credentials, 2)

	path := filepath.Join(t.TempDir(), "cc")
	require.NoError(t, c.Save("FILE:"+path))

	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())

	d, err := LoadCCache(path)
	require.NoError(t, err)

	off, ok := d.KDCOffset()
	assert.True(t, ok)
	assert.Equal(t, 900*time.Second-1500*time.Millisecond, off)

	v, ok := d.Config("fast_avail", "krbtgt/A.TEST@A.TEST")
	assert.True(t, ok)
	assert.Equal(t, "yes", string(v))

	got := d.GetEntries()
	require.Len(t, got, 1)
	assert.Equal(t, now.Add(11*time.Hour).Unix(), got[0].EndTime.Unix())
	assert.Equal(t, int64(1<<31+5), got[0].RenewTill.Unix())
	assert.Equal(t, cred.Key, got[0].Key)
}

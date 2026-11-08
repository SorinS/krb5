package keytab_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SorinS/krb5/iana/etypeID"
	"github.com/SorinS/krb5/iana/nametype"
	"github.com/SorinS/krb5/keytab"
	"github.com/SorinS/krb5/types"
)

// A program outside the package can read and change keytab entries: the Entry
// and Principal types and their fields are exported, and SetKVNO keeps the
// 8-bit and 32-bit versions consistent.
func TestEntryManipulation(t *testing.T) {
	kt := keytab.New()
	require.NoError(t, kt.AddEntry("svc-web", "GOOSE.TEST", "hello123", time.Unix(1000, 0), 1, etypeID.AES256_CTS_HMAC_SHA1_96))

	require.Len(t, kt.Entries, 1)

	// Read the entry's fields through the exported types.
	e := &kt.Entries[0]
	assert.Equal(t, "svc-web@GOOSE.TEST", e.Principal.String())
	assert.Equal(t, "GOOSE.TEST", e.Principal.Realm)
	assert.Equal(t, time.Unix(1000, 0), e.Timestamp)

	// Change the version (above the 8-bit range, as AD's can be) and timestamp.
	kvno := uint32(1000)
	e.SetKVNO(kvno)
	e.SetTimestamp(time.Unix(2000, 0))

	assert.Equal(t, kvno, e.KVNO)
	assert.Equal(t, uint8(kvno), e.KVNO8, "SetKVNO sets the 8-bit field to the low byte")

	// The changes survive a round trip.
	b, err := kt.Marshal()
	require.NoError(t, err)

	back := keytab.New()
	require.NoError(t, back.Unmarshal(b))
	require.Len(t, back.Entries, 1)
	assert.Equal(t, uint32(1000), back.Entries[0].KVNO)
	assert.Equal(t, time.Unix(2000, 0), back.Entries[0].Timestamp)

	_, gotKVNO, err := back.GetEncryptionKey(
		types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "svc-web"), "GOOSE.TEST", int(kvno), etypeID.AES256_CTS_HMAC_SHA1_96)
	require.NoError(t, err)
	assert.Equal(t, int(kvno), gotKVNO)
}

// An Entry can also be built and appended from outside the package.
func TestEntryConstruct(t *testing.T) {
	src := keytab.New()
	require.NoError(t, src.AddEntry("alice", "GOOSE.TEST", "pw", time.Unix(1, 0), 1, etypeID.AES128_CTS_HMAC_SHA1_96))

	e := keytab.Entry{
		Principal: keytab.Principal{
			NumComponents: 1,
			Realm:         "GOOSE.TEST",
			Components:    []string{"bob"},
			NameType:      nametype.KRB_NT_PRINCIPAL,
		},
		Key: src.Entries[0].Key,
	}
	e.SetKVNO(7)
	e.SetTimestamp(time.Unix(3, 0))

	kt := keytab.New()
	kt.Entries = append(kt.Entries, e)

	b, err := kt.Marshal()
	require.NoError(t, err)

	back := keytab.New()
	require.NoError(t, back.Unmarshal(b))
	require.Len(t, back.Entries, 1)
	assert.Equal(t, "bob@GOOSE.TEST", back.Entries[0].Principal.String())
	assert.Equal(t, uint32(7), back.Entries[0].KVNO)
}

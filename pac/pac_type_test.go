package pac

import (
	"bytes"
	"encoding/hex"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

func TestPACTypeVerify(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledPAC_AD_WIN2K_PAC)
	require.NoError(t, err)

	var pac PACType

	require.NoError(t, pac.Unmarshal(b))

	b, _ = hex.DecodeString(testdata.KEYTAB_SYSHTTP_TEST_GOKRB5)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))

	pn, _ := types.ParseSPNString("sysHTTP")

	key, _, err := kt.GetEncryptionKey(pn, "TEST.GOKRB5", 2, 18)
	require.NoError(t, err)

	w := bytes.NewBufferString("")
	l := log.New(w, "", 0)

	require.NoError(t, pac.ProcessPACInfoBuffers(key, l))

	v, err := pac.verify(key)
	assert.True(t, v)
	assert.NoError(t, err)

	// The server signature and the client info are needed; the logon info
	// (which MIT's PACs lack) and the KDC signature (which only the KDC can
	// check) are not.
	badSig := *pac.ServerChecksum
	badSig.Signature = append([]byte(nil), badSig.Signature...)
	badSig.Signature[0] ^= 0xFF

	pacInvalidServerSig := pac
	pacInvalidServerSig.ServerChecksum = &badSig
	pacNilKerbValidationInfo := pac
	pacNilKerbValidationInfo.KerbValidationInfo = nil
	pacInvalidNilServerSig := pac
	pacInvalidNilServerSig.ServerChecksum = nil
	pacNilKdcSig := pac
	pacNilKdcSig.KDCChecksum = nil
	pacInvalidClientInfo := pac
	pacInvalidClientInfo.ClientInfo = nil

	var pacs = []struct {
		pac PACType
		ok  bool
	}{
		{pacInvalidServerSig, false},
		{pacNilKerbValidationInfo, true},
		{pacInvalidNilServerSig, false},
		{pacNilKdcSig, true},
		{pacInvalidClientInfo, false},
	}

	for i, s := range pacs {
		v, err := s.pac.verify(key)
		assert.Equal(t, s.ok, v, "case %d", i)
		assert.Equal(t, s.ok, err == nil, "case %d: %v", i, err)
	}
}

// Info buffers outside the PAC are refused, not a panic.
func TestPACType_BufferOutsidePAC(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledPAC_AD_WIN2K_PAC)
	require.NoError(t, err)

	var whole PACType

	require.NoError(t, whole.Unmarshal(b))

	end := 0
	for _, buf := range whole.Buffers {
		end = max(end, int(buf.Offset)+int(buf.CBBufferSize))
	}

	for _, cut := range []int{end - 1, len(b) / 2, 100} {
		var pac PACType

		assert.Error(t, pac.Unmarshal(b[:cut]), "cut at %d", cut)
	}

	// A buffer of type 6 whose size is too small for a signature.
	var pac PACType

	require.NoError(t, pac.Unmarshal(b))

	key := types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)}
	for i := range pac.Buffers {
		if pac.Buffers[i].ULType == infoTypePACServerSignatureData {
			pac.Buffers[i].CBBufferSize = 2
		}
	}

	assert.Error(t, pac.ProcessPACInfoBuffers(key, log.New(bytes.NewBuffer(nil), "", 0)))
}

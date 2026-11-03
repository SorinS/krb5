package messages

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/test/testdata"
	"github.com/go-krb5/krb5/types"
)

func mitPACTicket(t *testing.T) (Ticket, types.EncryptionKey, types.EncryptionKey) {
	t.Helper()

	b, err := hex.DecodeString(testdata.MIT_PAC_TICKET)
	require.NoError(t, err)

	var tkt Ticket
	require.NoError(t, tkt.Unmarshal(b))

	s, err := hex.DecodeString(testdata.MIT_PAC_SERVICE_KEY)
	require.NoError(t, err)

	k, err := hex.DecodeString(testdata.MIT_PAC_KRBTGT_KEY)
	require.NoError(t, err)

	return tkt, types.EncryptionKey{KeyType: 18, KeyValue: s}, types.EncryptionKey{KeyType: 18, KeyValue: k}
}

func TestTicket_VerifyPACKDC(t *testing.T) {
	t.Parallel()

	tkt, skey, tgtKey := mitPACTicket(t)

	found, p, err := tkt.VerifyPACKDC(skey, tgtKey)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "alice", p.ClientInfo.Name)
	assert.NotNil(t, p.TicketChecksum)
	assert.NotNil(t, p.FullChecksum)

	wrong := types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)}
	_, _, err = tkt.VerifyPACKDC(skey, wrong)
	assert.ErrorContains(t, err, "KDC signature verification failed")

	_, _, err = tkt.VerifyPACKDC(wrong, tgtKey)
	assert.ErrorContains(t, err, "error decrypting")
}

// The ticket checksum is over the ticket with the PAC replaced by one zero
// byte: changing any other byte of the ticket fails it, and the PAC's own
// bytes are not in it.
func TestTicket_VerifyPACKDC_TicketChecksum(t *testing.T) {
	t.Parallel()

	tkt, skey, tgtKey := mitPACTicket(t)

	plain, err := crypto.DecryptEncPart(tkt.EncPart, skey, keyusage.KDC_REP_TICKET)
	require.NoError(t, err)

	recoded, pacData, found, err := ticketWithZeroPAC(plain)
	require.NoError(t, err)
	require.True(t, found)
	assert.True(t, bytes.Contains(plain, pacData))
	assert.False(t, bytes.Contains(recoded, pacData))

	// The recoded part is the ticket's, but for the PAC: one zero byte.
	var enc, orig EncTicketPart
	require.NoError(t, enc.Unmarshal(recoded))
	require.NoError(t, orig.Unmarshal(plain))

	var inner types.AuthorizationData
	require.NoError(t, inner.Unmarshal(enc.AuthorizationData[0].ADData))
	assert.Equal(t, []byte{0}, inner[0].ADData)

	enc.AuthorizationData, orig.AuthorizationData = nil, nil
	assert.Equal(t, orig, enc)

	tkt.DecryptedEncPart = EncTicketPart{}
	_, p, err := tkt.VerifyPACKDC(skey, tgtKey)
	require.NoError(t, err)
	require.NoError(t, p.VerifyTicketChecksum(tgtKey, recoded))

	for _, at := range []int{0, 10, len(recoded) / 2, len(recoded) - 1} {
		changed := append([]byte(nil), recoded...)
		changed[at] ^= 1
		assert.Error(t, p.VerifyTicketChecksum(tgtKey, changed), "byte %d", at)
	}

	_, _, found, err = ticketWithZeroPAC(plain[:len(plain)-1])
	assert.Error(t, err)
	assert.False(t, found)
}

// A change to the PAC breaks the server signature, which is checked first.
func TestTicket_VerifyPACKDC_ChangedPAC(t *testing.T) {
	t.Parallel()

	tkt, skey, tgtKey := mitPACTicket(t)

	plain, err := crypto.DecryptEncPart(tkt.EncPart, skey, keyusage.KDC_REP_TICKET)
	require.NoError(t, err)

	_, pacData, _, err := ticketWithZeroPAC(plain)
	require.NoError(t, err)

	// The client info's name ("alice" in UTF-16) is in the first buffer.
	at := bytes.Index(pacData, []byte{'a', 0, 'l', 0, 'i', 0})
	require.Positive(t, at)

	changed := append([]byte(nil), plain...)
	start := bytes.Index(changed, pacData)
	changed[start+at] = 'A'

	ed, err := crypto.GetEncryptedData(changed, skey, keyusage.KDC_REP_TICKET, tkt.EncPart.KVNO)
	require.NoError(t, err)

	tkt.EncPart = ed
	_, _, err = tkt.VerifyPACKDC(skey, tgtKey)
	assert.ErrorContains(t, err, "PAC service checksum verification failed")
}

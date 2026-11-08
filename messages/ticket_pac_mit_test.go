package messages_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SorinS/krb5/client"
	"github.com/SorinS/krb5/config"
	"github.com/SorinS/krb5/crypto"
	"github.com/SorinS/krb5/iana/nametype"
	"github.com/SorinS/krb5/keytab"
	"github.com/SorinS/krb5/test"
	"github.com/SorinS/krb5/types"
)

// An MIT KDC's service ticket (test/mitkdc): its PAC has client info and
// the server, KDC, ticket and full signatures, checked with the service's
// key and with the krbtgt key mitkdc.py exports.
func TestTicket_VerifyPACKDC_MIT(t *testing.T) {
	dir := test.MIT(t)

	cfg, err := config.Load(filepath.Join(dir, "krb5.conf"))
	require.NoError(t, err)

	cl := client.NewWithPassword("alice", "A.TEST", "alice-pw", cfg)
	require.NoError(t, cl.Login())

	svc, err := keytab.Load(filepath.Join(dir, "svc.keytab"))
	require.NoError(t, err)

	tgs, err := keytab.Load(filepath.Join(dir, "krbtgt.keytab"))
	require.NoError(t, err)

	krbtgt := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/A.TEST")

	for _, spn := range []string{"HTTP/svc.a.test", "host/svc.a.test"} {
		tkt, _, err := cl.GetServiceTicket(spn)
		require.NoError(t, err)

		skey, _, err := svc.GetEncryptionKey(tkt.SName, tkt.Realm, tkt.EncPart.KVNO, tkt.EncPart.EType)
		require.NoError(t, err)
		require.NoError(t, tkt.Decrypt(skey))

		// The service's own check: the server signature and the client info.
		isPAC, p, err := tkt.GetPACType(svc, nil, nil)
		require.NoError(t, err, spn)
		require.True(t, isPAC)
		assert.Nil(t, p.KerbValidationInfo, "MIT's PACs have no logon info")
		require.NotNil(t, p.KDCChecksum)
		require.NotNil(t, p.TicketChecksum)
		require.NotNil(t, p.FullChecksum)
		assert.Equal(t, "alice", p.ClientInfo.Name)

		// The krbtgt key of the KDC signature's type.
		et, err := crypto.GetChksumEtype(int32(p.KDCChecksum.SignatureType))
		require.NoError(t, err)

		tgtKey, _, err := tgs.GetEncryptionKey(krbtgt, "A.TEST", 0, et.GetETypeID())
		require.NoError(t, err)

		found, kp, err := tkt.VerifyPACKDC(skey, tgtKey)
		require.NoError(t, err, spn)
		assert.True(t, found)
		require.NoError(t, kp.VerifyKDCSignature(tgtKey))
		require.NoError(t, kp.VerifyFullChecksum(tgtKey))

		// Another key of the krbtgt's type fails every KDC signature.
		wrong := types.EncryptionKey{KeyType: tgtKey.KeyType, KeyValue: make([]byte, len(tgtKey.KeyValue))}
		_, _, err = tkt.VerifyPACKDC(skey, wrong)
		assert.Error(t, err)
		assert.Error(t, kp.VerifyKDCSignature(wrong))
		assert.Error(t, kp.VerifyFullChecksum(wrong))
		assert.Error(t, kp.VerifyTicketChecksum(wrong, nil))

		// A key of another type is refused for what it is.
		for _, e := range tgs.Entries {
			if e.Key.KeyType != tgtKey.KeyType {
				assert.ErrorContains(t, kp.VerifyKDCSignature(e.Key), "which the key's encryption type")
				break
			}
		}

		if spn == "HTTP/svc.a.test" && test.Capture() {
			b, err := tkt.Marshal()
			require.NoError(t, err)
			t.Logf("vector ticket %x", b)
			t.Logf("vector service key %d %x", skey.KeyType, skey.KeyValue)
			t.Logf("vector krbtgt key %d %x", tgtKey.KeyType, tgtKey.KeyValue)
		}
	}
}

package kadmin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/SorinS/krb5/iana/etypeID"
	"github.com/SorinS/krb5/iana/nametype"
	"github.com/SorinS/krb5/messages"
	"github.com/SorinS/krb5/types"
)

// sessionKey is a usable AES256 key for building a request in tests.
func testSessionKey(t *testing.T) types.EncryptionKey {
	t.Helper()

	return types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
}

// testTicket is a ticket to kadmin/changepw, enough to build a request (its
// SName picks the authenticator's key usage).
func testTicket() messages.Ticket {
	return messages.Ticket{SName: types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "kadmin/changepw")}
}

// userData decrypts the request's KRB-PRIV with the subkey and returns the
// carried bytes.
func userData(t *testing.T, r Request, subkey types.EncryptionKey) []byte {
	t.Helper()

	require.NoError(t, r.KRBPriv.DecryptEncPart(subkey))

	return r.KRBPriv.DecryptedEncPart.UserData
}

// A self change-password request uses version 1 and carries the new password
// directly, with no ChangePasswdData and no target principal (which is what a
// KDC accepts from the user without reset rights).
func TestChangePasswdMsg_ChangeForm(t *testing.T) {
	t.Parallel()

	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")

	r, subkey, err := ChangePasswdMsg(cname, "A.TEST", "new-pw", testTicket(), testSessionKey(t))
	require.NoError(t, err)

	assert.Equal(t, verChangePassword, r.Version)
	assert.Equal(t, []byte("new-pw"), userData(t, r, subkey), "version 1 carries the raw password")

	// The marshalled message begins (after the 2-byte length) with 0x0001.
	b, err := r.Marshal()
	require.NoError(t, err)
	assert.Equal(t, []byte{0x00, 0x01}, b[2:4])
}

// A set-password request uses version 0xff80 and carries ChangePasswdData with
// the target principal.
func TestSetPasswdMsg_SetForm(t *testing.T) {
	t.Parallel()

	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "admin")
	targ := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "bob")

	r, subkey, err := SetPasswdMsg(cname, "A.TEST", targ, "A.TEST", "new-pw", testTicket(), testSessionKey(t))
	require.NoError(t, err)

	assert.Equal(t, verSetPassword, r.Version)

	var cpd ChangePasswdData
	_, err = asn1Unmarshal(userData(t, r, subkey), &cpd)
	require.NoError(t, err)

	assert.Equal(t, []byte("new-pw"), cpd.NewPasswd)
	assert.Equal(t, "bob", cpd.TargName.PrincipalNameString())
	assert.Equal(t, "A.TEST", cpd.TargRealm)

	b, err := r.Marshal()
	require.NoError(t, err)
	assert.Equal(t, []byte{0xff, 0x80}, b[2:4])
}

func asn1Unmarshal(b []byte, v any) ([]byte, error) {
	return asn1.Unmarshal(b, v)
}

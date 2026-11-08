package messages

import (
	"bytes"
	"testing"

	"github.com/SorinS/krb5/iana/nametype"
	"github.com/SorinS/krb5/types"
)

// A decrypted ticket marshals as it came: its session key must not go out.
func TestTicketMarshal_LeavesOutDecryptedPart(t *testing.T) {
	t.Parallel()

	secret := bytes.Repeat([]byte{0x5a}, 32)
	tkt := Ticket{TktVNO: 5, Realm: "A.TEST", SName: types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/svc.a.test"),
		EncPart: types.EncryptedData{EType: 18, Cipher: []byte("cipher")}}

	want, err := tkt.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	tkt.DecryptedEncPart.Key = types.EncryptionKey{KeyType: 18, KeyValue: secret}
	tkt.DecryptedEncPart.CRealm = "A.TEST"

	got, err := tkt.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) || bytes.Contains(got, secret) {
		t.Errorf("the decrypted part went out: %x", got)
	}

	if len(tkt.DecryptedEncPart.Key.KeyValue) == 0 {
		t.Error("Marshal changed the ticket")
	}
}

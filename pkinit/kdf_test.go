package pkinit

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/types"
)

func cycle(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 17)
	}

	return b
}

// RFC 4556 Appendix B.
func TestOctetString2Key(t *testing.T) {
	t.Parallel()

	for _, v := range []struct {
		etype int32
		x     []byte
		want  string
	}{
		{18, make([]byte, 256), "5ee50d675c809fe59e4a7762c54b65837547eafb159bd8cdc75ffca5911e4c41"},
		{18, make([]byte, 128), "acf7707c08973ddfdb27cd361442ccfba355c8884cb472f37da636d07d56787e"},
		{18, cycle(128), "c442da585fcb80e43b47946f254093e37329d99001380db78371db3acf5c797e"},
		{18, cycle(77), "0053953b84c896f4eb385c3f2e751c4a590ed6ffadca6ff64f47ebeb8d780ffc"},
		{17, make([]byte, 256), "5ee50d675c809fe59e4a7762c54b6583"},
	} {
		k, err := OctetString2Key(v.etype, v.x)
		if err != nil || hex.EncodeToString(k.KeyValue) != v.want {
			t.Errorf("%d bytes, etype %d: %x, %v", len(v.x), v.etype, k.KeyValue, err)
		}
	}
}

// RFC 8636 8's vectors. The des3 one's key material is the key itself
// (random-to-key of the first 21 bytes), 24 bytes: the "32" it states is
// wrong.
func TestKDFVectors(t *testing.T) {
	t.Parallel()

	client := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "lha")
	server := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "krbtgt/SU.SE")
	asReq := bytes.Repeat([]byte{0xaa}, 10)
	rep := bytes.Repeat([]byte{0xbb}, 9)
	z := make([]byte, 256)

	for _, v := range []struct {
		kdf   KDF
		etype int32
		want  string
	}{
		{KDFSHA1, 18, "e6ab38c9413e035bb079201ed0b6b73d8d49a814a737c04ee6649614206f73ad"},
		{KDFSHA256, 18, "77ef4e48c420ae3fec75109d7981697eed5d295c90c62564f7bfd101fa9bc1d5"},
		{KDFSHA512, 16, "d3c78a79d65213efe9a826f75dfb01f72362fb16fb01dad6"},
	} {
		oi, err := OtherInfo(v.kdf, client, "SU.SE", server, "SU.SE", v.etype, asReq, rep)
		if err != nil {
			t.Fatal(err)
		}

		k, err := DeriveKey(v.kdf, v.etype, z, oi)
		if err != nil || hex.EncodeToString(k.KeyValue) != v.want {
			t.Errorf("KDF %v, etype %d: %x, %v", v.kdf, v.etype, k.KeyValue, err)
		}
	}
}

package messages

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/types"
)

// What VerifyS4U refuses of a reply: the client not the user, and a
// PA-S4U-X509-USER echo of another nonce, another user, or not signed in
// the request's subkey.
func TestVerifyS4U(t *testing.T) {
	t.Parallel()

	subkey, err := crypto.RandomKey(18)
	if err != nil {
		t.Fatal(err)
	}

	other, err := crypto.RandomKey(18)
	if err != nil {
		t.Fatal(err)
	}

	alice := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	mallory := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "mallory")

	req := TGSReq{SubKey: subkey, S4UUser: &S4UUser{Name: alice, Realm: "A.TEST"}}
	req.ReqBody.Nonce = 1234

	echo := func(name types.PrincipalName, nonce int64, key types.EncryptionKey, opts uint32, usage uint32) types.PAData {
		id := s4uUserID{Nonce: nonce, CName: name, CRealm: "A.TEST", Options: types.NewKrbFlags()}
		binary.BigEndian.PutUint32(id.Options.Bytes, opts)

		der, err := marshalKrb(id)
		if err != nil {
			t.Fatal(err)
		}

		et, _ := crypto.GetEtype(key.KeyType)

		ck, err := et.GetChecksumHash(key.KeyValue, der, usage)
		if err != nil {
			t.Fatal(err)
		}

		v, err := marshalKrb(paS4UX509User{UserID: id, Checksum: types.Checksum{CksumType: et.GetHashID(), Checksum: ck}})
		if err != nil {
			t.Fatal(err)
		}

		return types.PAData{PADataType: patype.PA_FOR_X509_USER, PADataValue: v}
	}

	rep := func(name types.PrincipalName, realm string, pa ...types.PAData) *TGSRep {
		return &TGSRep{KDCRepFields{CName: name, CRealm: realm, PAData: pa}}
	}

	const reply, request = keyusage.KEY_USAGE_PA_S4U_X509_USER_REPLY, keyusage.KEY_USAGE_PA_S4U_X509_USER_REQUEST

	for _, c := range []struct {
		what string
		rep  *TGSRep
		ok   bool
	}{
		{"an echo in the reply usage", rep(alice, "A.TEST", echo(alice, 1234, subkey, s4uOptUseReplyKeyUsage, reply)), true},
		{"an echo in the request usage", rep(alice, "A.TEST", echo(alice, 1234, subkey, 0, request)), true},
		{"no echo (an old KDC)", rep(alice, "A.TEST"), true},
		{"another client", rep(mallory, "A.TEST"), false},
		{"another realm", rep(alice, "B.TEST"), false},
		{"another nonce", rep(alice, "A.TEST", echo(alice, 1235, subkey, s4uOptUseReplyKeyUsage, reply)), false},
		{"another user echoed", rep(alice, "A.TEST", echo(mallory, 1234, subkey, s4uOptUseReplyKeyUsage, reply)), false},
		{"another key", rep(alice, "A.TEST", echo(alice, 1234, other, s4uOptUseReplyKeyUsage, reply)), false},
		{"the usage not the option's", rep(alice, "A.TEST", echo(alice, 1234, subkey, s4uOptUseReplyKeyUsage, request)), false},
	} {
		if err := c.rep.VerifyS4U(req); (err == nil) != c.ok {
			t.Errorf("%s: %v", c.what, err)
		}
	}

	// An enterprise name: the KDC may rewrite it, but the reply and its echo
	// must agree.
	ent := req
	ent.S4UUser = &S4UUser{Name: types.NewPrincipalName(nametype.KRB_NT_ENTERPRISE, "alice@a.test"), Realm: "A.TEST"}

	if err := rep(alice, "A.TEST", echo(alice, 1234, subkey, s4uOptUseReplyKeyUsage, reply)).VerifyS4U(ent); err != nil {
		t.Errorf("enterprise, rewritten: %v", err)
	}

	if err := rep(mallory, "A.TEST", echo(alice, 1234, subkey, s4uOptUseReplyKeyUsage, reply)).VerifyS4U(ent); err == nil {
		t.Error("enterprise: the reply's client not the echo's")
	}

	// By certificate: the KDC names the user, so the echo must be there.
	byCert := req
	byCert.S4UUser = &S4UUser{Realm: "A.TEST", Cert: []byte{0x30, 0x00}}

	for _, c := range []struct {
		what string
		rep  *TGSRep
		ok   bool
	}{
		{"the user the echo names", rep(alice, "A.TEST", echo(alice, 1234, subkey, s4uOptUseReplyKeyUsage, reply)), true},
		{"no echo", rep(alice, "A.TEST"), false},
		{"an echo naming nobody", rep(types.PrincipalName{}, "A.TEST", echo(types.PrincipalName{}, 1234, subkey, s4uOptUseReplyKeyUsage, reply)), false},
		{"the client not the echo's", rep(mallory, "A.TEST", echo(alice, 1234, subkey, s4uOptUseReplyKeyUsage, reply)), false},
		{"another realm", rep(alice, "B.TEST", echo(alice, 1234, subkey, s4uOptUseReplyKeyUsage, reply)), false},
		{"another nonce", rep(alice, "A.TEST", echo(alice, 1235, subkey, s4uOptUseReplyKeyUsage, reply)), false},
		{"another key", rep(alice, "A.TEST", echo(alice, 1234, other, s4uOptUseReplyKeyUsage, reply)), false},
	} {
		if err := c.rep.VerifyS4U(byCert); (err == nil) != c.ok {
			t.Errorf("by certificate, %s: %v", c.what, err)
		}
	}
}

// A request by certificate: PA-S4U-X509-USER with the certificate and no name,
// checksummed in the subkey, and no PA-FOR-USER, which needs a name.
func TestS4U2SelfReq_Cert(t *testing.T) {
	t.Parallel()

	service := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "svc")
	cert := []byte{0x30, 0x03, 0x02, 0x01, 0x07}
	now := time.Now()

	key, err := crypto.RandomKey(18)
	if err != nil {
		t.Fatal(err)
	}

	req, err := NewS4U2SelfReqAt(service, "A.TEST", "A.TEST", config.New(), Ticket{Realm: "A.TEST", SName: service}, key, S4UUser{Realm: "A.TEST", Cert: cert}, now)
	if err != nil {
		t.Fatal(err)
	}

	if req.PAData.Contains(patype.PA_FOR_USER) {
		t.Error("PA-FOR-USER in a request by certificate")
	}

	var got paS4UX509User

	for _, pa := range req.PAData {
		if pa.PADataType != patype.PA_FOR_X509_USER {
			continue
		}

		if _, err := asn1.Unmarshal(pa.PADataValue, &got, asn1.WithUnmarshalAllowTypeGeneralString(true)); err != nil {
			t.Fatal(err)
		}
	}

	if string(got.UserID.Cert) != string(cert) || len(got.UserID.CName.NameString) != 0 || got.UserID.CRealm != "A.TEST" {
		t.Errorf("the request's user: %+v", got.UserID)
	}

	der, err := marshalKrb(got.UserID)
	if err != nil {
		t.Fatal(err)
	}

	et, _ := crypto.GetEtype(req.SubKey.KeyType)
	if !et.VerifyChecksum(req.SubKey.KeyValue, der, got.Checksum.Checksum, keyusage.KEY_USAGE_PA_S4U_X509_USER_REQUEST) {
		t.Error("the checksum is not in the subkey")
	}

	// Neither a name nor a certificate.
	if _, err := NewS4U2SelfReqAt(service, "A.TEST", "A.TEST", config.New(), Ticket{Realm: "A.TEST", SName: service}, key, S4UUser{Realm: "A.TEST"}, now); err == nil {
		t.Error("a request naming nobody")
	}

	// A session key of a type whose checksum would not be keyed.
	rc4, err := crypto.RandomKey(23)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := NewS4U2SelfReqAt(service, "A.TEST", "A.TEST", config.New(), Ticket{Realm: "A.TEST", SName: service}, rc4, S4UUser{Realm: "A.TEST", Cert: cert}, now); err == nil {
		t.Error("by certificate with an RC4 subkey")
	}
}

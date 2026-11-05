package client_test

import (
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/test"
	"github.com/go-krb5/krb5/types"
)

// assertS4UEcho makes the S4U2Self exchange itself, to see that the KDC's
// reply has the PA-S4U-X509-USER that VerifyS4U checks.
func assertS4UEcho(t *testing.T, cl *client.Client, user types.PrincipalName, realm string) {
	t.Helper()

	a, err := cl.Armor()
	require.NoError(t, err)

	req, err := messages.NewS4U2SelfReqAt(cl.Credentials.CName(), realm, realm, cl.Config, a.Ticket, a.SessionKey,
		messages.S4UUser{Name: user, Realm: realm}, cl.Now())
	require.NoError(t, err)

	_, rep, err := cl.TGSExchange(req, realm, a.Ticket, a.SessionKey, 0)
	require.NoError(t, err)

	var echoed bool

	for _, pa := range rep.PAData {
		echoed = echoed || pa.PADataType == patype.PA_FOR_X509_USER
	}

	assert.True(t, echoed, "no PA-S4U-X509-USER in the reply")
}

// S4U against MIT 1.22's A.TEST (test/mitkdc): S4U2Self, the ticket's
// client and flags read with the service's keytab; S4U2Proxy, which MIT's
// DB2 back end refuses (its own t_s4u.py expects so).
func TestClient_S4U_MIT(t *testing.T) {
	dir := test.MIT(t)
	cfg := mitConfig(t, dir)

	kt, err := keytab.Load(filepath.Join(dir, "s4u.keytab"))
	require.NoError(t, err)

	alice := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")

	// Plain and armored (a KDC that does FAST: implicit armor by the TGT).
	for _, disableFAST := range []bool{true, false} {
		rec := &recordingDialer{}
		cl := client.NewWithKeytab("HTTP/proxy.a.test", "A.TEST", kt, cfg, client.UseDialer(rec), client.DisablePAFXFAST(disableFAST))
		require.NoError(t, cl.Login())

		tkt, key, err := cl.GetServiceTicketForUser(alice, "A.TEST")
		require.NoError(t, err)
		require.NotEmpty(t, key.KeyValue)

		require.NoError(t, tkt.DecryptEncPart(kt, nil))
		assert.Equal(t, "alice", tkt.DecryptedEncPart.CName.PrincipalNameString())
		assert.Equal(t, "A.TEST", tkt.DecryptedEncPart.CRealm)
		assert.Equal(t, "HTTP/proxy.a.test", tkt.SName.PrincipalNameString())
		assert.True(t, types.IsFlagSet(&tkt.DecryptedEncPart.Flags, flags.Forwardable), "ok_to_auth_as_delegate")

		for _, b := range rec.sent() {
			if b[0] != 0x6c {
				continue
			}

			var r messages.TGSReq
			require.NoError(t, r.Unmarshal(b))

			if disableFAST {
				assert.True(t, r.PAData.Contains(patype.PA_FOR_USER))
				assert.True(t, r.PAData.Contains(patype.PA_FOR_X509_USER))
			} else {
				assert.True(t, r.PAData.Contains(patype.PA_FX_FAST), "armored")
				assert.False(t, r.PAData.Contains(patype.PA_FOR_USER), "PA-FOR-USER outside the armor")
			}
		}

		// The client's own tickets are not confused with the user's.
		own, _, err := cl.GetServiceTicket("HTTP/proxy.a.test")
		require.NoError(t, err)
		require.NoError(t, own.DecryptEncPart(kt, nil))
		assert.Equal(t, "HTTP/proxy.a.test", own.DecryptedEncPart.CName.PrincipalNameString())

		// DB2 does not do S4U2Proxy.
		_, _, err = cl.GetServiceTicketForProxy("HTTP/svc.a.test", tkt)
		require.Error(t, err)

		var kerr messages.KRBError
		require.True(t, errors.As(err, &kerr), "%v", err)
		assert.Equal(t, errorcode.KDC_ERR_BADOPTION, kerr.ErrorCode)
	}

	// Without ok_to_auth_as_delegate: a ticket, forwardable all the same: MIT
	// (s4u2self_forwardable) denies it only to a service with classic
	// delegation targets, which DB2 cannot have.
	cl := client.NewWithKeytab("HTTP/self.a.test", "A.TEST", kt, cfg)
	require.NoError(t, cl.Login())

	tkt, _, err := cl.GetServiceTicketForUser(alice, "A.TEST")
	require.NoError(t, err)
	require.NoError(t, tkt.DecryptEncPart(kt, nil))
	assert.True(t, types.IsFlagSet(&tkt.DecryptedEncPart.Flags, flags.Forwardable))

	// The KDC echoes PA-S4U-X509-USER, which VerifyS4U then checks.
	assertS4UEcho(t, cl, alice, "A.TEST")

	// An RC4 session key: no PA-S4U-X509-USER (its checksum would be
	// unkeyed), so the KDC goes by PA-FOR-USER's HMAC-MD5.
	rc4 := mitConfigWith(t, dir, "default_tkt_enctypes = arcfour-hmac", "", "")
	rec := &recordingDialer{}
	byName := client.NewWithKeytab("HTTP/proxy.a.test", "A.TEST", kt, rc4, client.UseDialer(rec), client.DisablePAFXFAST(true))
	require.NoError(t, byName.Login())

	tkt, _, err = byName.GetServiceTicketForUser(alice, "A.TEST")
	require.NoError(t, err)
	require.NoError(t, tkt.DecryptEncPart(kt, nil))
	assert.Equal(t, "alice", tkt.DecryptedEncPart.CName.PrincipalNameString())

	var checked bool

	for _, b := range rec.sent() {
		var r messages.TGSReq
		if b[0] == 0x6c && r.Unmarshal(b) == nil {
			assert.True(t, r.PAData.Contains(patype.PA_FOR_USER))
			assert.False(t, r.PAData.Contains(patype.PA_FOR_X509_USER))

			checked = true
		}
	}

	assert.True(t, checked)

	// A user the KDC does not know, and one in another realm.
	_, _, err = cl.GetServiceTicketForUser(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "nobody"), "A.TEST")
	require.Error(t, err)

	var kerr messages.KRBError
	require.True(t, errors.As(err, &kerr), "%v", err)
	assert.Equal(t, errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, kerr.ErrorCode)

	_, _, err = cl.GetServiceTicketForUser(alice, "K.TEST")
	require.ErrorContains(t, err, "another realm")
}

// S4U2Self by certificate: MIT's DB2 back end cannot map one. That the KDC gets
// as far as asking it says the request decoded and its checksum verified: a
// bad one gets another answer.
func TestClient_S4UCert_MIT(t *testing.T) {
	dir := test.MIT(t)
	cfg := mitConfig(t, dir)

	kt, err := keytab.Load(filepath.Join(dir, "s4u.keytab"))
	require.NoError(t, err)

	cl := client.NewWithKeytab("HTTP/proxy.a.test", "A.TEST", kt, cfg)
	require.NoError(t, cl.Login())

	_, _, err = cl.GetServiceTicketForCertificate(&x509.Certificate{Raw: []byte{0x30, 0x03, 0x02, 0x01, 0x07}})
	require.Error(t, err)

	var kerr messages.KRBError
	require.True(t, errors.As(err, &kerr), "%v", err)
	t.Logf("%v", err)

	log, err := os.ReadFile(filepath.Join(dir, "kdc-a.log"))
	require.NoError(t, err)
	assert.Contains(t, string(log), "LOOKING_UP_S4U2SELF_PRINCIPAL")

	_, _, err = cl.GetServiceTicketForCertificate(nil)
	require.Error(t, err)
}

package client_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SorinS/krb5/client"
	"github.com/SorinS/krb5/config"
	"github.com/SorinS/krb5/iana/errorcode"
	"github.com/SorinS/krb5/iana/flags"
	"github.com/SorinS/krb5/iana/nametype"
	"github.com/SorinS/krb5/keytab"
	"github.com/SorinS/krb5/messages"
	"github.com/SorinS/krb5/pac"
	"github.com/SorinS/krb5/test"
	"github.com/SorinS/krb5/types"
)

// readPAC decrypts a ticket with its service account's password (the account
// named, of the ticket's realm, its key by the default salt, the kvno the
// ticket's) and reads its PAC.
func readPAC(t *testing.T, tkt *messages.Ticket, account, password string) pac.PACType {
	t.Helper()

	kt := keytab.New()
	require.NoError(t, kt.AddEntry(account, tkt.Realm, password, time.Now(), uint8(tkt.EncPart.KVNO), tkt.EncPart.EType))

	name := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, account)
	require.NoError(t, tkt.DecryptEncPart(kt, &name))

	isPAC, p, err := tkt.GetPACType(kt, &name, nil)
	require.NoError(t, err)
	require.True(t, isPAC)
	require.NotNil(t, p.KerbValidationInfo)

	return p
}

// Cross-realm S4U2Self against two live AD forests with a two-way trust: the
// service of the default realm (svc-proxy, protocol transition) gets a
// ticket to itself in the name of the peer realm's alice and bob, by way of
// the peer's KDC. The ticket, read with the service's key, has the user of
// the peer realm as its client and in its PAC. (The other direction is the
// same test with the two realms' TEST_AD_DIR and TEST_AD_PEER_REALM swapped.)
func TestClient_S4UCrossRealm_AD(t *testing.T) {
	dir, password, peer := test.ADPeerRealm(t)

	cfg, err := config.Load(filepath.Join(dir, "krb5.conf"))
	require.NoError(t, err)

	home, domain := test.ADDomain(t, cfg.LibDefaults.DefaultRealm)

	proxy := client.NewWithPassword("svc-proxy", home, password, cfg)
	require.NoError(t, proxy.Login())

	for _, user := range []string{"alice", "bob"} {
		name := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, user)

		self, _, err := proxy.GetServiceTicketForUser(name, peer)
		require.NoError(t, err, "svc-proxy@%s for %s@%s", home, user, peer)

		assert.Equal(t, "svc-proxy", self.SName.PrincipalNameString(), "the service's own name, not the enterprise one")
		assert.Equal(t, home, self.Realm)

		p := readPAC(t, &self, "svc-proxy", password)
		assert.Equal(t, user, self.DecryptedEncPart.CName.PrincipalNameString())
		assert.Equal(t, peer, self.DecryptedEncPart.CRealm)
		assert.Equal(t, user, p.ClientInfo.Name)
	}

	// A user the peer realm does not have.
	_, _, err = proxy.GetServiceTicketForUser(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "nobody"), peer)

	var kerr messages.KRBError
	require.True(t, errors.As(err, &kerr), "%v", err)
	assert.Equal(t, errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, kerr.ErrorCode)

	// The service's own session is still its own: a ticket for itself in its
	// own name, after the referrals that carried the users' PACs.
	own, _, err := proxy.GetServiceTicket("HTTP/proxy." + domain)
	require.NoError(t, err)
	readPAC(t, &own, "svc-proxy", password)
	assert.Equal(t, "svc-proxy", own.DecryptedEncPart.CName.PrincipalNameString())
}

// S4U against a live AD (test/ad/s4u.ps1 set up the accounts).
func TestClient_S4U_AD(t *testing.T) {
	dir, password := test.ADLive(t)

	cfg, err := config.Load(filepath.Join(dir, "krb5.conf"))
	require.NoError(t, err)

	realm, domain := test.ADDomain(t, cfg.LibDefaults.DefaultRealm)

	// A forwardable TGT: S4U2Self's ticket can be no more forwardable than
	// it (and alice's ticket, below).
	cfg.LibDefaults.Forwardable = true

	login := func(name string) *client.Client {
		cl := client.NewWithPassword(name, realm, password, cfg)
		require.NoError(t, cl.Login(), name)

		return cl
	}

	badOption := func(err error, what string) {
		t.Helper()
		require.Error(t, err, what)

		var kerr messages.KRBError
		require.True(t, errors.As(err, &kerr), "%s: %v", what, err)
		assert.Contains(t, []int32{errorcode.KDC_ERR_BADOPTION, errorcode.KDC_ERR_POLICY}, kerr.ErrorCode, what)
	}

	alice := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	proxy := login("svc-proxy")

	// Protocol transition: a forwardable ticket to svc-proxy in alice's
	// name, with alice's PAC.
	self, _, err := proxy.GetServiceTicketForUser(alice, realm)
	require.NoError(t, err)

	p := readPAC(t, &self, "svc-proxy", password)
	assert.Equal(t, "alice", self.DecryptedEncPart.CName.PrincipalNameString())
	assert.Equal(t, "alice", p.ClientInfo.Name)
	assert.True(t, types.IsFlagSet(&self.DecryptedEncPart.Flags, flags.Forwardable))

	assertS4UEcho(t, proxy, alice, realm)

	// By enterprise name too.
	ent, _, err := proxy.GetServiceTicketForUser(types.NewPrincipalName(nametype.KRB_NT_ENTERPRISE, "alice@"+domain), realm)
	require.NoError(t, err)
	readPAC(t, &ent, "svc-proxy", password)
	assert.Equal(t, "alice@"+domain, ent.DecryptedEncPart.CName.PrincipalNameString(), "AD keeps the name asked for")

	// Constrained delegation to the service it may delegate to, with the
	// transited service in the PAC.
	target, skey, err := proxy.GetServiceTicketForProxy("HTTP/target."+domain, self)
	require.NoError(t, err)
	require.NotEmpty(t, skey.KeyValue)

	p = readPAC(t, &target, "svc-target", password)
	assert.Equal(t, "alice", target.DecryptedEncPart.CName.PrincipalNameString())
	assert.Equal(t, "alice", p.ClientInfo.Name)
	require.NotNil(t, p.S4UDelegationInfo)
	assert.Equal(t, "HTTP/target."+domain, p.S4UDelegationInfo.S4U2proxyTarget.Value)

	// The same with a user's ticket given to the service, not made by
	// S4U2Self: alice's own, forwardable, ticket to svc-proxy.
	user := login("alice")
	own, _, err := user.GetServiceTicket("HTTP/proxy." + domain)
	require.NoError(t, err)

	viaOwn, _, err := proxy.GetServiceTicketForProxy("HTTP/target."+domain, own)
	require.NoError(t, err)
	p = readPAC(t, &viaOwn, "svc-target", password)
	assert.Equal(t, "alice", p.ClientInfo.Name)

	// Not to a service it may not delegate to.
	_, _, err = proxy.GetServiceTicketForProxy("HTTP/rbcdt."+domain, self)
	badOption(err, "a target not allowed")

	// Delegation targets without protocol transition: S4U2Self's ticket is
	// not forwardable and no use to S4U2Proxy; the user's own ticket is.
	kerb := login("svc-kerb")
	kt, _, err := kerb.GetServiceTicketForUser(alice, realm)
	require.NoError(t, err)
	readPAC(t, &kt, "svc-kerb", password)
	assert.False(t, types.IsFlagSet(&kt.DecryptedEncPart.Flags, flags.Forwardable))

	_, _, err = kerb.GetServiceTicketForProxy("HTTP/target."+domain, kt)
	badOption(err, "a non-forwardable S4U2Self ticket")

	ownK, _, err := user.GetServiceTicket("HTTP/kerb." + domain)
	require.NoError(t, err)

	_, _, err = kerb.GetServiceTicketForProxy("HTTP/target."+domain, ownK)
	require.NoError(t, err)

	// No delegation configured: a forwardable ticket all the same (Server
	// 2022, as MIT), which S4U2Proxy still refuses.
	plain := login("svc-self")
	st, _, err := plain.GetServiceTicketForUser(alice, realm)
	require.NoError(t, err)
	readPAC(t, &st, "svc-self", password)
	assert.True(t, types.IsFlagSet(&st.DecryptedEncPart.Flags, flags.Forwardable))

	_, _, err = plain.GetServiceTicketForProxy("HTTP/target."+domain, st)
	badOption(err, "a service without delegation")

	// A sensitive user: S4U2Proxy refused, however allowed the service.
	sens, _, err := proxy.GetServiceTicketForUser(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "sens"), realm)
	require.NoError(t, err)
	readPAC(t, &sens, "svc-proxy", password)
	assert.False(t, types.IsFlagSet(&sens.DecryptedEncPart.Flags, flags.Forwardable))

	_, _, err = proxy.GetServiceTicketForProxy("HTTP/target."+domain, sens)
	badOption(err, "a sensitive user")

	// Resource-based: the target lets svc-rbcd, which has no delegation of
	// its own.
	rbcd := login("svc-rbcd")
	rs, _, err := rbcd.GetServiceTicketForUser(alice, realm)
	require.NoError(t, err)
	readPAC(t, &rs, "svc-rbcd", password)

	rt, _, err := rbcd.GetServiceTicketForProxy("HTTP/rbcdt."+domain, rs)
	require.NoError(t, err)
	p = readPAC(t, &rt, "svc-rbcdt", password)
	assert.Equal(t, "alice", p.ClientInfo.Name)

	_, _, err = rbcd.GetServiceTicketForProxy("HTTP/target."+domain, rs)
	badOption(err, "a target that does not allow it")

	// Armored, as a machine would: FAST's implicit armor on the S4U requests.
	armor, err := client.NewWithPassword("goosepc$", realm, password, cfg).Armor()
	require.NoError(t, err)

	armored := client.NewWithPassword("svc-proxy", realm, password, cfg, client.FASTArmor(armor))
	require.NoError(t, armored.Login())

	as, _, err := armored.GetServiceTicketForUser(alice, realm)
	require.NoError(t, err)
	readPAC(t, &as, "svc-proxy", password)

	at, _, err := armored.GetServiceTicketForProxy("HTTP/target."+domain, as)
	require.NoError(t, err)
	readPAC(t, &at, "svc-target", password)
}

// s4uCertSKI is the subject key identifier certie is mapped to (test/ad/s4u.ps1).
var s4uCertSKI = []byte("goose-s4u-certie-ski")

// s4uCert is an RSA client certificate with the subject key identifier given,
// valid in the time given, issued by a CA made here, which the DC does not
// know.
func s4uCert(t *testing.T, ski []byte, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Goose Test"}, CommonName: "Goose S4U CA"},
		NotBefore:             notBefore.Add(-time.Hour),
		NotAfter:              notAfter.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	require.NoError(t, err)

	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{Organization: []string{"Goose Test"}, CommonName: "somebody"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SubjectKeyId:          ski,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
	require.NoError(t, err)

	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return c
}

// S4U2Self by certificate against a live AD (test/ad/s4u.ps1 maps certie).
func TestClient_S4UCert_AD(t *testing.T) {
	dir, password := test.ADLive(t)

	cfg, err := config.Load(filepath.Join(dir, "krb5.conf"))
	require.NoError(t, err)

	realm, domain := test.ADDomain(t, cfg.LibDefaults.DefaultRealm)

	cfg.LibDefaults.Forwardable = true

	proxy := client.NewWithPassword("svc-proxy", realm, password, cfg)
	require.NoError(t, proxy.Login())

	now := time.Now()
	cert := s4uCert(t, s4uCertSKI, now.Add(-time.Hour), now.Add(time.Hour))

	// The KDC finds the user: the name comes from the reply, checked by
	// VerifyS4U against the echo, and the PAC agrees.
	self, _, err := proxy.GetServiceTicketForCertificate(cert)
	require.NoError(t, err)

	p := readPAC(t, &self, "svc-proxy", password)
	assert.Equal(t, "certie", self.DecryptedEncPart.CName.PrincipalNameString())
	assert.Equal(t, realm, self.DecryptedEncPart.CRealm)
	assert.Equal(t, "certie", p.ClientInfo.Name)
	assert.True(t, types.IsFlagSet(&self.DecryptedEncPart.Flags, flags.Forwardable))

	// It goes on to S4U2Proxy as any S4U2Self ticket does.
	target, _, err := proxy.GetServiceTicketForProxy("HTTP/target."+domain, self)
	require.NoError(t, err)

	p = readPAC(t, &target, "svc-target", password)
	assert.Equal(t, "certie", p.ClientInfo.Name)
	require.NotNil(t, p.S4UDelegationInfo)

	// Armored by FAST too.
	armor, err := proxy.Armor()
	require.NoError(t, err)

	armored := client.NewWithPassword("svc-proxy", realm, password, cfg, client.FASTArmor(armor))
	require.NoError(t, armored.Login())

	as, _, err := armored.GetServiceTicketForCertificate(cert)
	require.NoError(t, err)
	assert.Equal(t, "certie", readPAC(t, &as, "svc-proxy", password).ClientInfo.Name)

	// A service with delegation targets but no protocol transition gets a
	// ticket that is not forwardable, as by name.
	kerb := client.NewWithPassword("svc-kerb", realm, password, cfg)
	require.NoError(t, kerb.Login())

	kt, _, err := kerb.GetServiceTicketForCertificate(cert)
	require.NoError(t, err)

	readPAC(t, &kt, "svc-kerb", password)
	assert.False(t, types.IsFlagSet(&kt.DecryptedEncPart.Flags, flags.Forwardable))

	// A certificate mapped to nobody.
	_, _, err = proxy.GetServiceTicketForCertificate(s4uCert(t, []byte("goose-s4u-nobody-ski"), now.Add(-time.Hour), now.Add(time.Hour)))
	require.Error(t, err)

	var kerr messages.KRBError
	require.True(t, errors.As(err, &kerr), "%v", err)
	assert.Equal(t, errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, kerr.ErrorCode)

	// The CA above is unknown to the DC, and an expired certificate does as
	// well (Server 2022): what the caller does not check, nobody does.
	_, _, err = proxy.GetServiceTicketForCertificate(s4uCert(t, s4uCertSKI, now.Add(-48*time.Hour), now.Add(-24*time.Hour)))
	t.Logf("expired: %v", err)

	// Refused here, before any KDC sees it.
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	_, _, err = proxy.GetServiceTicketForCertificate(&x509.Certificate{Raw: []byte{0x30}, PublicKeyAlgorithm: x509.Ed25519, PublicKey: key.Public()})
	require.Error(t, err)
	assert.False(t, errors.As(err, &kerr))
}

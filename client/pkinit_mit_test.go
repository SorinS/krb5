package client_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/pkinit"
	"github.com/go-krb5/krb5/test"
	"github.com/go-krb5/krb5/types"
)

// mitConfigWith is the MIT test krb5.conf with lines added to
// [libdefaults] and to a realm's block.
func mitConfigWith(t *testing.T, dir, libdefaults, realm, realmLines string) *config.Config {
	t.Helper()

	conf, err := os.ReadFile(filepath.Join(dir, "krb5.conf"))
	require.NoError(t, err)

	s := string(conf)
	if libdefaults != "" {
		s = strings.Replace(s, "[libdefaults]", "[libdefaults]\n    "+libdefaults, 1)
	}

	if realm != "" {
		s = strings.Replace(s, "    "+realm+" = {", "    "+realm+" = {\n        "+realmLines, 1)
	}

	cfg, err := config.NewFromString(s)
	require.NoError(t, err)

	return cfg
}

func identity(t *testing.T, dir, name string) *pkinit.Identity {
	t.Helper()

	p := filepath.Join(dir, "pki", name)
	certs := p + ".pem"

	// pat-inter's certificate goes with its intermediate CA's.
	if name == "pat-inter" {
		leaf, err := os.ReadFile(p + ".pem")
		require.NoError(t, err)

		inter, err := os.ReadFile(filepath.Join(dir, "pki", "inter.pem"))
		require.NoError(t, err)

		certs = filepath.Join(t.TempDir(), "bundle.pem")
		require.NoError(t, os.WriteFile(certs, append(leaf, inter...), 0o600))
	}

	id, err := pkinit.LoadIdentity("FILE:" + certs + "," + p + ".key")
	require.NoError(t, err, name)

	return id
}

// PKINIT against MIT 1.22's P/Q/R/N.TEST (test/mitkdc), its certificates
// made by OpenSSL (test/mitkdc/pki.py).
func TestClient_PKINIT_MIT(t *testing.T) {
	dir := test.MIT(t)
	cfg := mitConfig(t, dir)

	// pat's identities: RSA 2048, ECDSA on the three curves, RSA 3072 with
	// SHA-384, and one issued by an intermediate CA sent along.
	for _, name := range []string{"pat", "pat-p256", "pat-p384", "pat-p521", "pat-rsa3072", "pat-inter"} {
		cl := client.NewWithPKINIT("pat", "P.TEST", identity(t, dir, name), cfg)
		require.NoError(t, cl.Login(), name)

		tkt, _, err := cl.GetServiceTicket("HTTP/svc.p.test")
		require.NoError(t, err, name)
		assert.Equal(t, "P.TEST", tkt.Realm)
	}

	// Each DH group the client can start with (pkinit_dh_min_bits).
	for _, g := range []string{"2048", "P-256", "4096", "P-384", "P-521"} {
		c := mitConfigWith(t, dir, "pkinit_dh_min_bits = "+g, "", "")
		cl := client.NewWithPKINIT("pat", "P.TEST", identity(t, dir, "pat"), c)
		require.NoError(t, cl.Login(), g)
	}

	// No KDF offered: the KDC uses RFC 4556's octetstring2key.
	c := mitConfigWith(t, dir, "pkinit_kdfs = none", "", "")
	require.NoError(t, client.NewWithPKINIT("pat", "P.TEST", identity(t, dir, "pat"), c).Login())

	// Q.TEST wants groups of 4096 bits and up, and freshness tokens: our
	// 2048 is refused, the KDC's list picks 4096; the token is asked for.
	require.NoError(t, client.NewWithPKINIT("quinn", "Q.TEST", identity(t, dir, "quinn"), cfg).Login())

	// R.TEST's KDC certificate names it by host name only: refused, unless
	// pkinit_kdc_hostname takes it.
	err := client.NewWithPKINIT("rita", "R.TEST", identity(t, dir, "rita"), cfg).Login()
	require.Error(t, err)

	var pe *pkinit.Error
	require.True(t, errors.As(err, &pe), "%v", err)

	c = mitConfigWith(t, dir, "", "R.TEST", "pkinit_kdc_hostname = kdc.r.test")
	require.NoError(t, client.NewWithPKINIT("rita", "R.TEST", identity(t, dir, "rita"), c).Login())

	// N.TEST's KDC certificate has the id-pkinit-san but EKU serverAuth:
	// the SAN suffices, as MIT has it.
	require.NoError(t, client.NewWithPKINIT("nate", "N.TEST", identity(t, dir, "rita"), cfg).Login())

	// The KDC refuses a certificate from an untrusted CA, and an expired one.
	for _, name := range []string{"pat-other", "pat-expired"} {
		require.Error(t, client.NewWithPKINIT("pat", "P.TEST", identity(t, dir, name), cfg).Login(), name)
	}

	// We refuse a KDC whose certificate does not chain to our anchors.
	conf, err := os.ReadFile(filepath.Join(dir, "krb5.conf"))
	require.NoError(t, err)

	rogue, err := config.NewFromString(strings.ReplaceAll(string(conf), "/pki/ca.pem", "/pki/rogue.pem"))
	require.NoError(t, err)

	err = client.NewWithPKINIT("pat", "P.TEST", identity(t, dir, "pat"), rogue).Login()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KDC_NOT_TRUSTED")
}

// Anonymous PKINIT (RFC 8062): a TGT for WELLKNOWN/ANONYMOUS, which then
// armors pat's password login with FAST.
func TestClient_PKINIT_Anonymous_MIT(t *testing.T) {
	dir := test.MIT(t)
	cfg := mitConfig(t, dir)

	anon := client.NewAnonymous("P.TEST", cfg)
	require.NoError(t, anon.Login())

	armor, err := anon.Armor()
	require.NoError(t, err)
	assert.Equal(t, client.AnonymousRealm, armor.CRealm)

	cc, err := anon.CCache()
	require.NoError(t, err)

	tgt, ok := cc.GetEntry(types.PrincipalName{NameType: 2, NameString: []string{"krbtgt", "P.TEST"}})
	require.True(t, ok)
	assert.True(t, types.IsFlagSet(&tgt.TicketFlags, flags.Anonymous))

	rec := &recordingDialer{}
	cl := client.NewWithPassword("pat", "P.TEST", "pat-pw", cfg, client.FASTArmor(armor), client.UseDialer(rec))
	require.NoError(t, cl.Login())

	var armored bool

	for _, b := range rec.sent() {
		var r messages.ASReq
		if b[0] == 0x6a && r.Unmarshal(b) == nil && len(r.PAData) == 1 {
			armored = true
		}
	}

	assert.True(t, armored)
}

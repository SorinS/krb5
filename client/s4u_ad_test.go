package client_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/pac"
	"github.com/go-krb5/krb5/test"
	"github.com/go-krb5/krb5/types"
)

// readPAC decrypts a ticket with its service account's password (the account
// named, its key by the default salt, the kvno the ticket's) and reads
// its PAC.
func readPAC(t *testing.T, tkt *messages.Ticket, account, password string) pac.PACType {
	t.Helper()

	kt := keytab.New()
	require.NoError(t, kt.AddEntry(account, "GOOSE.TEST", password, time.Now(), uint8(tkt.EncPart.KVNO), tkt.EncPart.EType))

	name := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, account)
	require.NoError(t, tkt.DecryptEncPart(kt, &name))

	isPAC, p, err := tkt.GetPACType(kt, &name, nil)
	require.NoError(t, err)
	require.True(t, isPAC)
	require.NotNil(t, p.KerbValidationInfo)

	return p
}

// S4U against a live AD (test/ad/s4u.ps1 set up the accounts).
func TestClient_S4U_AD(t *testing.T) {
	dir, password := test.ADLive(t)

	cfg, err := config.Load(filepath.Join(dir, "krb5.conf"))
	require.NoError(t, err)

	// A forwardable TGT: S4U2Self's ticket can be no more forwardable than
	// it (and alice's ticket, below).
	cfg.LibDefaults.Forwardable = true

	login := func(name string) *client.Client {
		cl := client.NewWithPassword(name, "GOOSE.TEST", password, cfg)
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
	self, _, err := proxy.GetServiceTicketForUser(alice, "GOOSE.TEST")
	require.NoError(t, err)

	p := readPAC(t, &self, "svc-proxy", password)
	assert.Equal(t, "alice", self.DecryptedEncPart.CName.PrincipalNameString())
	assert.Equal(t, "alice", p.ClientInfo.Name)
	assert.True(t, types.IsFlagSet(&self.DecryptedEncPart.Flags, flags.Forwardable))

	assertS4UEcho(t, proxy, alice, "GOOSE.TEST")

	// By enterprise name too.
	ent, _, err := proxy.GetServiceTicketForUser(types.NewPrincipalName(nametype.KRB_NT_ENTERPRISE, "alice@goose.test"), "GOOSE.TEST")
	require.NoError(t, err)
	readPAC(t, &ent, "svc-proxy", password)
	assert.Equal(t, "alice@goose.test", ent.DecryptedEncPart.CName.PrincipalNameString(), "AD keeps the name asked for")

	// Constrained delegation to the service it may delegate to, with the
	// transited service in the PAC.
	target, skey, err := proxy.GetServiceTicketForProxy("HTTP/target.goose.test", self)
	require.NoError(t, err)
	require.NotEmpty(t, skey.KeyValue)

	p = readPAC(t, &target, "svc-target", password)
	assert.Equal(t, "alice", target.DecryptedEncPart.CName.PrincipalNameString())
	assert.Equal(t, "alice", p.ClientInfo.Name)
	require.NotNil(t, p.S4UDelegationInfo)
	assert.Equal(t, "HTTP/target.goose.test", p.S4UDelegationInfo.S4U2proxyTarget.Value)

	// The same with a user's ticket given to the service, not made by
	// S4U2Self: alice's own, forwardable, ticket to svc-proxy.
	user := login("alice")
	own, _, err := user.GetServiceTicket("HTTP/proxy.goose.test")
	require.NoError(t, err)

	viaOwn, _, err := proxy.GetServiceTicketForProxy("HTTP/target.goose.test", own)
	require.NoError(t, err)
	p = readPAC(t, &viaOwn, "svc-target", password)
	assert.Equal(t, "alice", p.ClientInfo.Name)

	// Not to a service it may not delegate to.
	_, _, err = proxy.GetServiceTicketForProxy("HTTP/rbcdt.goose.test", self)
	badOption(err, "a target not allowed")

	// Delegation targets without protocol transition: S4U2Self's ticket is
	// not forwardable and no use to S4U2Proxy; the user's own ticket is.
	kerb := login("svc-kerb")
	kt, _, err := kerb.GetServiceTicketForUser(alice, "GOOSE.TEST")
	require.NoError(t, err)
	readPAC(t, &kt, "svc-kerb", password)
	assert.False(t, types.IsFlagSet(&kt.DecryptedEncPart.Flags, flags.Forwardable))

	_, _, err = kerb.GetServiceTicketForProxy("HTTP/target.goose.test", kt)
	badOption(err, "a non-forwardable S4U2Self ticket")

	ownK, _, err := user.GetServiceTicket("HTTP/kerb.goose.test")
	require.NoError(t, err)

	_, _, err = kerb.GetServiceTicketForProxy("HTTP/target.goose.test", ownK)
	require.NoError(t, err)

	// No delegation configured: a forwardable ticket all the same (Server
	// 2022, as MIT), which S4U2Proxy still refuses.
	plain := login("svc-self")
	st, _, err := plain.GetServiceTicketForUser(alice, "GOOSE.TEST")
	require.NoError(t, err)
	readPAC(t, &st, "svc-self", password)
	assert.True(t, types.IsFlagSet(&st.DecryptedEncPart.Flags, flags.Forwardable))

	_, _, err = plain.GetServiceTicketForProxy("HTTP/target.goose.test", st)
	badOption(err, "a service without delegation")

	// A sensitive user: S4U2Proxy refused, however allowed the service.
	sens, _, err := proxy.GetServiceTicketForUser(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "sens"), "GOOSE.TEST")
	require.NoError(t, err)
	readPAC(t, &sens, "svc-proxy", password)
	assert.False(t, types.IsFlagSet(&sens.DecryptedEncPart.Flags, flags.Forwardable))

	_, _, err = proxy.GetServiceTicketForProxy("HTTP/target.goose.test", sens)
	badOption(err, "a sensitive user")

	// Resource-based: the target lets svc-rbcd, which has no delegation of
	// its own.
	rbcd := login("svc-rbcd")
	rs, _, err := rbcd.GetServiceTicketForUser(alice, "GOOSE.TEST")
	require.NoError(t, err)
	readPAC(t, &rs, "svc-rbcd", password)

	rt, _, err := rbcd.GetServiceTicketForProxy("HTTP/rbcdt.goose.test", rs)
	require.NoError(t, err)
	p = readPAC(t, &rt, "svc-rbcdt", password)
	assert.Equal(t, "alice", p.ClientInfo.Name)

	_, _, err = rbcd.GetServiceTicketForProxy("HTTP/target.goose.test", rs)
	badOption(err, "a target that does not allow it")

	// Armored, as a machine would: FAST's implicit armor on the S4U requests.
	armor, err := client.NewWithPassword("goosepc$", "GOOSE.TEST", password, cfg).Armor()
	require.NoError(t, err)

	armored := client.NewWithPassword("svc-proxy", "GOOSE.TEST", password, cfg, client.FASTArmor(armor))
	require.NoError(t, armored.Login())

	as, _, err := armored.GetServiceTicketForUser(alice, "GOOSE.TEST")
	require.NoError(t, err)
	readPAC(t, &as, "svc-proxy", password)

	at, _, err := armored.GetServiceTicketForProxy("HTTP/target.goose.test", as)
	require.NoError(t, err)
	readPAC(t, &at, "svc-target", password)
}

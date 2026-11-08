package client_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SorinS/krb5/client"
	"github.com/SorinS/krb5/config"
	"github.com/SorinS/krb5/iana/patype"
	"github.com/SorinS/krb5/keytab"
	"github.com/SorinS/krb5/messages"
	"github.com/SorinS/krb5/test"
)

// FAST with a live AD (its "KDC support for claims, compound authentication
// and Kerberos armoring" on): alice's login armored by the computer
// goosepc$'s TGT, and her service ticket's TGS request armored explicitly
// by it too, which gives the ticket's PAC goosepc$'s device info and claims
// (compound identity: svc-web allows it).
func TestClient_FAST_AD(t *testing.T) {
	dir, password := test.ADLive(t)

	cfg, err := config.Load(filepath.Join(dir, "krb5.conf"))
	require.NoError(t, err)

	realm, domain := test.ADDomain(t, cfg.LibDefaults.DefaultRealm)

	kt, err := keytab.Load(filepath.Join(dir, "web.keytab"))
	require.NoError(t, err)

	device := client.NewWithPassword("goosepc$", realm, password, cfg)
	armor, err := device.Armor()
	require.NoError(t, err)

	rec := &recordingDialer{}
	cl := client.NewWithPassword("alice", realm, password, cfg, client.FASTArmor(armor), client.UseDialer(rec))
	require.NoError(t, cl.Login())

	for _, b := range rec.sent() {
		if b[0] == 0x6a {
			var r messages.ASReq
			require.NoError(t, r.Unmarshal(b))
			require.Len(t, r.PAData, 1)
			assert.Equal(t, patype.PA_FX_FAST, r.PAData[0].PADataType)
		}
	}

	// Implicit armor only: no device in the PAC.
	tkt, _, err := cl.GetServiceTicket("HTTP/web." + domain)
	require.NoError(t, err)
	require.NoError(t, tkt.DecryptEncPart(kt, nil))

	isPAC, p, err := tkt.GetPACType(kt, nil, nil)
	require.NoError(t, err)
	require.True(t, isPAC)
	assert.Nil(t, p.DeviceInfo)

	// Explicit armor by the device: its info in the PAC.
	cl = client.NewWithPassword("alice", realm, password, cfg, client.FASTArmor(armor), client.FASTDeviceArmor(armor))
	require.NoError(t, cl.Login())

	tkt, _, err = cl.GetServiceTicket("HTTP/web." + domain)
	require.NoError(t, err)
	require.NoError(t, tkt.DecryptEncPart(kt, nil))

	isPAC, p, err = tkt.GetPACType(kt, nil, nil)
	require.NoError(t, err)
	require.True(t, isPAC)
	require.NotNil(t, p.DeviceInfo, "compound identity")
	assert.Equal(t, "alice", p.ClientInfo.Name)

	var compounded bool

	for _, s := range p.KerbValidationInfo.ExtraSIDs {
		if s.SID.String() == "S-1-5-21-0-0-0-496" {
			compounded = true
		}
	}

	assert.True(t, compounded, "the Compounded Authentication SID")

	// A wrong password, armored: AD's error from inside the armor.
	cl = client.NewWithPassword("alice", realm, "wrong", cfg, client.FASTArmor(armor))
	require.Error(t, cl.Login())
}

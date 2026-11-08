package messages_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SorinS/krb5/client"
	"github.com/SorinS/krb5/config"
	"github.com/SorinS/krb5/keytab"
	"github.com/SorinS/krb5/test"
)

// A live AD's service ticket: the PAC's server signature and client info
// check out with the service's keytab, and the PAC has the KDC's ticket
// and full checksums (the KDC signatures need the domain's krbtgt key,
// which only the DC has: they are checked against MIT, above).
func TestTicket_PAC_AD(t *testing.T) {
	dir, password := test.ADLive(t)

	cfg, err := config.Load(filepath.Join(dir, "krb5.conf"))
	require.NoError(t, err)

	realm, domain := test.ADDomain(t, cfg.LibDefaults.DefaultRealm)

	kt, err := keytab.Load(filepath.Join(dir, "web.keytab"))
	require.NoError(t, err)

	for _, user := range []string{"alice", "bob"} {
		cl := client.NewWithPassword(user, realm, password, cfg)
		require.NoError(t, cl.Login(), user)

		tkt, _, err := cl.GetServiceTicket("HTTP/web." + domain)
		require.NoError(t, err)
		require.NoError(t, tkt.DecryptEncPart(kt, nil))

		isPAC, p, err := tkt.GetPACType(kt, nil, nil)
		require.NoError(t, err, user)
		require.True(t, isPAC)
		require.NotNil(t, p.KerbValidationInfo)
		assert.Equal(t, user, p.ClientInfo.Name)
		assert.NotNil(t, p.KDCChecksum)
		assert.NotNil(t, p.TicketChecksum, "AD signs the ticket since November 2022")
		assert.NotNil(t, p.FullChecksum)

		// Another user's ticket does not pass for this one's.
		other := tkt
		other.DecryptedEncPart.CName.NameString = []string{user + "x"}
		_, _, err = other.GetPACType(kt, nil, nil)
		assert.ErrorContains(t, err, "is not the ticket's client")
	}
}

package ldap_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SorinS/krb5/client"
	"github.com/SorinS/krb5/config"
	"github.com/SorinS/krb5/gsskrb5"
	"github.com/SorinS/krb5/keytab"
	"github.com/SorinS/krb5/ldap"
	"github.com/SorinS/krb5/test"
)

// A live Active Directory's LDAP (TEST_AD_LDAP, its address; TEST_AD_DC_HOST,
// the DC's name, whose service is ldap/NAME): SASL GSSAPI binds with each
// layer, Who am I?, alice's SID to her entry, and her tokenGroups the
// PAC's domain groups.
func TestAD_LDAP(t *testing.T) {
	dir, password := test.ADLive(t)

	addr, host := os.Getenv("TEST_AD_LDAP"), os.Getenv("TEST_AD_DC_HOST")
	if addr == "" || host == "" {
		t.Skip("TEST_AD_LDAP or TEST_AD_DC_HOST is not set (see test/ad/README.md)")
	}

	cfg, err := config.Load(filepath.Join(dir, "krb5.conf"))
	require.NoError(t, err)

	cl := client.NewWithPassword("alice", "GOOSE.TEST", password, cfg)
	require.NoError(t, cl.Login())

	for _, layer := range []byte{gsskrb5.LayerConfidentiality, gsskrb5.LayerIntegrity, gsskrb5.LayerNone} {
		c, err := ldap.Dial(addr)
		require.NoError(t, err)

		require.NoError(t, c.BindGSSAPI(cl, "ldap@"+host, layer), "layer %d", layer)
		assert.Equal(t, layer, c.Layer())

		who, err := c.WhoAmI()
		require.NoError(t, err)
		assert.Regexp(t, regexp.MustCompile(`^u:\w+\\alice$`), who, "layer %d", layer)

		base, err := c.DefaultNamingContext()
		require.NoError(t, err)
		assert.Equal(t, "DC=goose,DC=test", base)

		if layer != gsskrb5.LayerConfidentiality {
			require.NoError(t, c.Close())
			continue
		}

		// alice's SID and groups, from her PAC.
		kt, err := keytab.Load(filepath.Join(dir, "web.keytab"))
		require.NoError(t, err)

		tkt, _, err := cl.GetServiceTicket("HTTP/web.goose.test")
		require.NoError(t, err)
		require.NoError(t, tkt.DecryptEncPart(kt, nil))

		_, p, err := tkt.GetPACType(kt, nil, nil)
		require.NoError(t, err)

		v := p.KerbValidationInfo
		domain := v.LogonDomainID.String()
		userSID := domain + "-" + strconv.FormatUint(uint64(v.UserID), 10)

		e, err := c.LookupSID(base, userSID)
		require.NoError(t, err)
		assert.Equal(t, "alice", e.Get("sAMAccountName"))
		assert.True(t, strings.HasPrefix(e.DN, "CN=alice,"), e.DN)

		sid, err := ldap.SIDString(e.Attributes["objectSid"][0])
		require.NoError(t, err)
		assert.Equal(t, userSID, sid)

		groups, err := c.TokenGroups(e.DN)
		require.NoError(t, err)

		var mine, pacs []string
		for _, g := range groups {
			if strings.HasPrefix(g, domain+"-") {
				mine = append(mine, g)
			}
		}

		for _, g := range v.GetGroupMembershipSIDs() {
			if strings.HasPrefix(g, domain+"-") {
				pacs = append(pacs, g)
			}
		}

		sort.Strings(mine)
		sort.Strings(pacs)
		assert.Equal(t, pacs, mine, "tokenGroups and the PAC's domain groups")
		assert.NotEmpty(t, mine)

		_, err = c.LookupSID(base, domain+"-999999")
		assert.Error(t, err)

		require.NoError(t, c.Close())
	}
}

package client_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SorinS/krb5/client"
	"github.com/SorinS/krb5/config"
	"github.com/SorinS/krb5/test"
)

// Camellia against MIT: with only camellia128-cts-cmac or
// camellia256-cts-cmac allowed, bob's AS exchange (his keys from his
// password, PA-ENC-TIMESTAMP, which the KDC requires of him) and a TGS
// exchange, every session key Camellia.
func TestClient_Camellia_MIT(t *testing.T) {
	dir := test.MIT(t)

	conf, err := os.ReadFile(filepath.Join(dir, "krb5.conf"))
	require.NoError(t, err)

	for _, et := range []struct {
		name string
		id   int32
	}{{"camellia128-cts-cmac", 25}, {"camellia256-cts-cmac", 26}} {
		c := strings.Replace(string(conf), "[libdefaults]", "[libdefaults]\n    default_tkt_enctypes = "+et.name+
			"\n    default_tgs_enctypes = "+et.name, 1)

		cfg, err := config.NewFromString(c)
		require.NoError(t, err)

		cl := client.NewWithPassword("bob", "A.TEST", "bob-pw", cfg)
		require.NoError(t, cl.Login(), et.name)

		tkt, key, err := cl.GetServiceTicket("HTTP/svc.a.test")
		require.NoError(t, err, et.name)
		assert.Equal(t, et.id, key.KeyType, "%s session key", et.name)
		assert.Equal(t, int32(18), tkt.EncPart.EType, "the service's own key is aes256")

		cc, err := cl.CCache()
		require.NoError(t, err)

		for _, e := range cc.GetEntries() {
			assert.Equal(t, et.id, e.Key.KeyType, "%s: %s", et.name, e.Server.PrincipalName.PrincipalNameString())
		}
	}
}

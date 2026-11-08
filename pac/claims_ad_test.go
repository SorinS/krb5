package pac_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-krb5/x/rpc/mstypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SorinS/krb5/client"
	"github.com/SorinS/krb5/config"
	"github.com/SorinS/krb5/keytab"
	"github.com/SorinS/krb5/test"
)

// A live AD's claims (test/ad/claims.ps1): carol's six string claims
// make a ClaimsSet the KDC compresses (LZ77+Huffman); alice's one claim
// (department) it does not.
func TestPAC_Claims_AD(t *testing.T) {
	dir, password := test.ADLive(t)

	cfg, err := config.Load(filepath.Join(dir, "krb5.conf"))
	require.NoError(t, err)

	kt, err := keytab.Load(filepath.Join(dir, "web.keytab"))
	require.NoError(t, err)

	claims := func(user string) (uint16, map[string]string) {
		cl := client.NewWithPassword(user, "GOOSE.TEST", password, cfg)
		require.NoError(t, cl.Login(), user)

		tkt, _, err := cl.GetServiceTicket("HTTP/web.goose.test")
		require.NoError(t, err)
		require.NoError(t, tkt.DecryptEncPart(kt, nil))

		isPAC, p, err := tkt.GetPACType(kt, nil, nil)
		require.NoError(t, err, user)
		require.True(t, isPAC)
		require.NotNil(t, p.ClientClaimsInfo, user)

		got := map[string]string{}
		for _, a := range p.ClientClaimsInfo.ClaimsSet.ClaimsArrays {
			for _, e := range a.ClaimEntries {
				require.Equal(t, mstypes.ClaimTypeIDString, e.Type, e.ID)
				var vs []string
				for _, v := range e.TypeString.Value {
					vs = append(vs, v.Value)
				}
				got[e.ID] = strings.Join(vs, ",")
			}
		}

		return p.ClientClaimsInfo.ClaimsSetMetadata.CompressionFormat, got
	}

	format, got := claims("alice")
	assert.Equal(t, mstypes.CompressionFormatNone, format)
	assert.Equal(t, map[string]string{"ad://ext/department:goose": "Engineering"}, got)

	format, got = claims("carol")
	assert.Equal(t, mstypes.CompressionFormatXPressHuff, format, "carol's claims are compressed")
	require.Len(t, got, 6)

	for _, a := range []string{"title", "company", "streetAddress", "physicalDeliveryOfficeName", "displayName", "l"} {
		v := got["ad://ext/"+a+":goose"]
		assert.True(t, strings.HasPrefix(v, "carol's "+a+": value of"), "%s: %q", a, v)
		assert.Len(t, v, 64, a)
	}
}

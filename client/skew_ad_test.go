package client_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SorinS/krb5/client"
	"github.com/SorinS/krb5/config"
	"github.com/SorinS/krb5/test"
)

// A live AD with the client's clock 20 minutes off (its offset set so):
// AD's KRB_AP_ERR_SKEW to the encrypted timestamp, and to the TGS
// request's authenticator, put the client right.
func TestClient_ClockSkew_AD(t *testing.T) {
	dir, password := test.ADLive(t)

	cfg, err := config.Load(filepath.Join(dir, "krb5.conf"))
	require.NoError(t, err)

	realm, domain := test.ADDomain(t, cfg.LibDefaults.DefaultRealm)

	cl := client.NewWithPassword("alice", realm, password, cfg)
	cl.SetTimeOffset(-20 * time.Minute)
	require.NoError(t, cl.Login())
	assert.Less(t, cl.TimeOffset().Abs(), 5*time.Second, "offset %v", cl.TimeOffset())

	cl.SetTimeOffset(20 * time.Minute)

	_, _, err = cl.GetServiceTicket("HTTP/web." + domain)
	require.NoError(t, err)
	assert.Less(t, cl.TimeOffset().Abs(), 5*time.Second, "offset %v", cl.TimeOffset())
}

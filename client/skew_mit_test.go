package client_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/test"
)

// K.TEST's KDC runs 900 seconds ahead of us (test/mitkdc, krb5kdc -T), three
// times the allowed skew. With kdc_timesync (the default) the client learns
// the KDC's time from its KRB_AP_ERR_SKEW error, as MIT does, and gets its
// tickets; without it, the KDC's error reaches the caller.
func TestClient_ClockSkew_MIT(t *testing.T) {
	dir := test.MIT(t)

	conf, err := os.ReadFile(filepath.Join(dir, "krb5.conf"))
	require.NoError(t, err)

	cfg, err := config.NewFromString(string(conf))
	require.NoError(t, err)
	require.Equal(t, 1, cfg.LibDefaults.KDCTimeSync)

	near := func(d time.Duration) bool {
		return d > 890*time.Second && d < 910*time.Second
	}

	cl := client.NewWithPassword("kim", "K.TEST", "kim-pw", cfg)
	require.NoError(t, cl.Login())
	assert.True(t, near(cl.TimeOffset()), "offset %v", cl.TimeOffset())

	tkt, _, err := cl.GetServiceTicket("HTTP/svc.k.test")
	require.NoError(t, err)
	assert.Equal(t, "K.TEST", tkt.Realm)

	// The TGS exchange learns it too: the offset forgotten, the KDC's skew
	// error sets it again and the request is made once more.
	cl.SetTimeOffset(0)

	_, _, err = cl.GetServiceTicket("host/none.k.test")
	require.Error(t, err, "no such service")
	assert.True(t, near(cl.TimeOffset()), "offset %v after the TGS exchange", cl.TimeOffset())

	// The KDC's error, with kdc_timesync off: errors.As finds it.
	off, err := config.NewFromString(strings.Replace(string(conf), "[libdefaults]", "[libdefaults]\n    kdc_timesync = 0", 1))
	require.NoError(t, err)
	require.Equal(t, 0, off.LibDefaults.KDCTimeSync)

	cl = client.NewWithPassword("kim", "K.TEST", "kim-pw", off)
	err = cl.Login()
	require.Error(t, err)

	var kerr messages.KRBError
	require.True(t, errors.As(err, &kerr), "%v", err)
	assert.Equal(t, errorcode.KRB_AP_ERR_SKEW, kerr.ErrorCode)
	assert.Equal(t, time.Duration(0), cl.TimeOffset())

	// A.TEST's KDC keeps our time: the offset stays near zero.
	cl = client.NewWithPassword("bob", "A.TEST", "bob-pw", cfg)
	require.NoError(t, cl.Login())
	assert.Less(t, cl.TimeOffset().Abs(), 2*time.Second)
}

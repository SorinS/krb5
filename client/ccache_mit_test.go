package client_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SorinS/krb5/client"
	"github.com/SorinS/krb5/config"
	"github.com/SorinS/krb5/credentials"
	"github.com/SorinS/krb5/keytab"
	"github.com/SorinS/krb5/test"
)

func mitTool(t *testing.T, dir, bin, cache string, args ...string) string {
	t.Helper()

	cmd := exec.Command(filepath.Join(bin, args[0]), args[1:]...)
	cmd.Env = append(os.Environ(), "KRB5_CONFIG="+filepath.Join(dir, "krb5.conf"), "KRB5CCNAME=FILE:"+cache)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s: %s", strings.Join(args, " "), out)

	return string(out)
}

// The client's cache, written: MIT's klist reads it (TGT, service ticket,
// their flags); MIT's kvno gets a ticket with its TGT; Heimdal's klist (on
// macOS, /usr/bin/klist) reads it too. And a cache MIT's kinit wrote gives
// a client its TGT.
func TestClient_SaveCCache_MIT(t *testing.T) {
	dir := test.MIT(t)
	bin := test.MITBin(t)

	cfg, err := config.Load(filepath.Join(dir, "krb5.conf"))
	require.NoError(t, err)

	cl := client.NewWithPassword("bob", "A.TEST", "bob-pw", cfg)
	require.NoError(t, cl.Login())

	_, _, err = cl.GetServiceTicket("HTTP/svc.a.test")
	require.NoError(t, err)

	cache := filepath.Join(t.TempDir(), "cc")
	require.NoError(t, cl.SaveCCache(cache))

	fi, err := os.Stat(cache)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())

	out := mitTool(t, dir, bin, cache, "klist", "-f", "-e")
	assert.Contains(t, out, "Default principal: bob@A.TEST")
	assert.Contains(t, out, "krbtgt/A.TEST@A.TEST")
	assert.Contains(t, out, "HTTP/svc.a.test@A.TEST")
	assert.Contains(t, out, "Flags: FRIA", "the TGT's flags")
	assert.Contains(t, out, "aes256-cts-hmac-sha1-96")

	// MIT uses our TGT: a ticket for another service, added to our cache.
	out = mitTool(t, dir, bin, cache, "kvno", "host/svc.a.test")
	assert.Contains(t, out, "host/svc.a.test@A.TEST: kvno =")

	c, err := credentials.LoadCCache(cache)
	require.NoError(t, err)
	assert.Len(t, c.GetEntries(), 3)

	// Heimdal's klist, where the system has it (macOS): it prints
	// "Credentials cache:", MIT's "Ticket cache:".
	if v, err := exec.Command("/usr/bin/klist", "--version").CombinedOutput(); err == nil && strings.Contains(string(v), "Heimdal") {
		h, err := exec.Command("/usr/bin/klist", "-c", "FILE:"+cache).CombinedOutput()
		require.NoError(t, err, string(h))
		assert.Contains(t, string(h), "Principal: bob@A.TEST")
		assert.Contains(t, string(h), "krbtgt/A.TEST@A.TEST")
		assert.Contains(t, string(h), "HTTP/svc.a.test@A.TEST")
		assert.Contains(t, string(h), "host/svc.a.test@A.TEST")
	}

	// MIT's cache to a client: its TGT gets a service ticket.
	mit := filepath.Join(t.TempDir(), "mit")
	cmd := exec.Command(filepath.Join(bin, "kinit"), "-c", "FILE:"+mit, "alice")
	cmd.Env = append(os.Environ(), "KRB5_CONFIG="+filepath.Join(dir, "krb5.conf"))
	cmd.Stdin = strings.NewReader("alice-pw\n")
	o, err := cmd.CombinedOutput()
	require.NoError(t, err, string(o))

	mc, err := credentials.LoadCCache(mit)
	require.NoError(t, err)

	cl2, err := client.NewFromCCache(mc, cfg)
	require.NoError(t, err)

	tkt, _, err := cl2.GetServiceTicket("HTTP/svc.a.test")
	require.NoError(t, err)

	kt, err := keytab.Load(filepath.Join(dir, "svc.keytab"))
	require.NoError(t, err)
	require.NoError(t, tkt.DecryptEncPart(kt, nil))
	assert.Equal(t, "alice", tkt.DecryptedEncPart.CName.PrincipalNameString())
}

// K.TEST's KDC is 900 s ahead: the offset the client learned goes in the
// cache's header, and MIT's kvno, which reads it (kdc_timesync), gets a
// ticket with our TGT that its own clock would make it fail to get.
func TestClient_SaveCCache_KDCOffset_MIT(t *testing.T) {
	dir := test.MIT(t)
	bin := test.MITBin(t)

	cfg, err := config.Load(filepath.Join(dir, "krb5.conf"))
	require.NoError(t, err)

	cl := client.NewWithPassword("kim", "K.TEST", "kim-pw", cfg)
	require.NoError(t, cl.Login())

	cache := filepath.Join(t.TempDir(), "cc")
	require.NoError(t, cl.SaveCCache(cache))

	c, err := credentials.LoadCCache(cache)
	require.NoError(t, err)

	d, ok := c.KDCOffset()
	assert.True(t, ok)
	assert.InDelta(t, 900, d.Seconds(), 10)

	out := mitTool(t, dir, bin, cache, "kvno", "HTTP/svc.k.test@K.TEST")
	assert.Contains(t, out, "HTTP/svc.k.test@K.TEST: kvno =")

	// Without the offset, MIT's kvno is refused for skew.
	c.SetKDCOffset(0)
	require.NoError(t, c.Save(cache))

	cmd := exec.Command(filepath.Join(bin, "kvno"), "HTTP/svc.k.test@K.TEST")
	cmd.Env = append(os.Environ(), "KRB5_CONFIG="+filepath.Join(dir, "krb5.conf"), "KRB5CCNAME=FILE:"+cache)
	o, err := cmd.CombinedOutput()
	assert.Error(t, err)
	t.Logf("kvno without the offset: %s", strings.TrimSpace(string(o)))

	// A client from the cache takes its offset.
	c.SetKDCOffset(900 * time.Second)
	cl2, err := client.NewFromCCache(c, cfg)
	require.NoError(t, err)
	assert.Equal(t, 900*time.Second, cl2.TimeOffset())
}

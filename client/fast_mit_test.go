package client_test

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/test"
)

func mitConfig(t *testing.T, dir string) *config.Config {
	t.Helper()

	conf, err := os.ReadFile(filepath.Join(dir, "krb5.conf"))
	require.NoError(t, err)

	cfg, err := config.NewFromString(string(conf))
	require.NoError(t, err)

	return cfg
}

// fastHost is host/fast.f.test's client (no pre-authentication, so its
// keytab gets its TGT unarmored): its TGT is F.TEST's armor.
func fastHost(t *testing.T, dir string, cfg *config.Config, keytabName, realm string) *client.Client {
	t.Helper()

	kt, err := keytab.Load(filepath.Join(dir, keytabName))
	require.NoError(t, err)

	host := "host/fast." + strings.ToLower(realm[:1]) + ".test"
	cl := client.NewWithKeytab(host, realm, kt, cfg)
	require.NoError(t, cl.Login())

	return cl
}

// F.TEST's KDC has no encrypted timestamp: grace's password works only
// through FAST's encrypted challenge, armored by host/fast.f.test's TGT.
func TestClient_FAST_MIT(t *testing.T) {
	dir := test.MIT(t)
	cfg := mitConfig(t, dir)

	armor, err := fastHost(t, dir, cfg, "fast.keytab", "F.TEST").Armor()
	require.NoError(t, err)

	// Unarmored, the KDC offers nothing a password can do.
	cl := client.NewWithPassword("grace", "F.TEST", "grace-pw", cfg)
	require.Error(t, cl.Login())

	rec := &recordingDialer{}
	cl = client.NewWithPassword("grace", "F.TEST", "grace-pw", cfg, client.FASTArmor(armor), client.UseDialer(rec))
	require.NoError(t, cl.Login())

	// The TGS exchange is armored too (the KDC said it does FAST).
	tkt, _, err := cl.GetServiceTicket("HTTP/svc.f.test")
	require.NoError(t, err)
	assert.Equal(t, "F.TEST", tkt.Realm)

	// What went out: every request armored, the AS requests' padata
	// PA-FX-FAST alone, the TGS request's PA-TGS-REQ and PA-FX-FAST.
	var as, tgs int

	for _, b := range rec.sent() {
		switch b[0] {
		case 0x6a:
			var r messages.ASReq
			require.NoError(t, r.Unmarshal(b))
			require.Len(t, r.PAData, 1)
			assert.Equal(t, patype.PA_FX_FAST, r.PAData[0].PADataType)

			as++
		case 0x6c:
			var r messages.TGSReq
			require.NoError(t, r.Unmarshal(b))
			require.Len(t, r.PAData, 2)
			assert.Equal(t, patype.PA_TGS_REQ, r.PAData[0].PADataType)
			assert.Equal(t, patype.PA_FX_FAST, r.PAData[1].PADataType)

			tgs++
		}
	}

	assert.GreaterOrEqual(t, as, 2)
	assert.Equal(t, 1, tgs)

	// A wrong password: the KDC's error, from inside the armor.
	cl = client.NewWithPassword("grace", "F.TEST", "wrong", cfg, client.FASTArmor(armor))
	err = cl.Login()
	require.Error(t, err)

	var kerr messages.KRBError
	require.True(t, errors.As(err, &kerr), "%v", err)
	assert.Equal(t, errorcode.KDC_ERR_PREAUTH_FAILED, kerr.ErrorCode)

	// An armor for another realm armors nothing here.
	cl = client.NewWithPassword("alice", "A.TEST", "alice-pw", cfg, client.FASTArmor(armor))
	require.Error(t, cl.Login())

	// A.TEST takes the timestamp and offers encrypted challenge inside
	// FAST: bob, armored by alice's TGT, uses the challenge.
	alice := client.NewWithPassword("alice", "A.TEST", "alice-pw", cfg)
	aArmor, err := alice.Armor()
	require.NoError(t, err)

	cl = client.NewWithPassword("bob", "A.TEST", "bob-pw", cfg, client.FASTArmor(aArmor))
	require.NoError(t, cl.Login())

	_, _, err = cl.GetServiceTicket("HTTP/svc.a.test")
	require.NoError(t, err)
}

// recordingDialer records the KDC requests sent through it (UDP's, and
// TCP's without their length).
type recordingDialer struct {
	mu   sync.Mutex
	reqs [][]byte
}

func (d *recordingDialer) Dial(network, addr string) (net.Conn, error) {
	c, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	return &recordingConn{Conn: c, d: d, tcp: network == "tcp"}, nil
}

func (d *recordingDialer) sent() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()

	return append([][]byte(nil), d.reqs...)
}

type recordingConn struct {
	net.Conn
	d   *recordingDialer
	tcp bool
	buf []byte
}

func (c *recordingConn) Write(b []byte) (int, error) {
	c.buf = append(c.buf, b...)

	msg := c.buf
	if c.tcp {
		if len(msg) < 4 || len(msg) < 4+int(binary.BigEndian.Uint32(msg)) {
			return c.Conn.Write(b)
		}

		msg = msg[4:]
	}

	c.d.mu.Lock()
	c.d.reqs = append(c.d.reqs, append([]byte(nil), msg...))
	c.d.mu.Unlock()
	c.buf = nil

	return c.Conn.Write(b)
}

// MIT's kinit as the oracle of our armor caches, and our client of its:
// kinit -T with host/fast.f.test's TGT in a cache we wrote, and our client
// armored by a cache MIT's kinit -k wrote.
func TestClient_FAST_MITKinit(t *testing.T) {
	dir := test.MIT(t)
	bin := test.MITBin(t)
	cfg := mitConfig(t, dir)
	tmp := t.TempDir()

	ours := filepath.Join(tmp, "armor-ours")
	require.NoError(t, fastHost(t, dir, cfg, "fast.keytab", "F.TEST").SaveCCache(ours))

	kinit := exec.Command(filepath.Join(bin, "kinit"), "-T", ours, "-c", filepath.Join(tmp, "grace"), "grace@F.TEST")
	kinit.Env = append(os.Environ(), "KRB5_CONFIG="+filepath.Join(dir, "krb5.conf"))
	kinit.Stdin = strings.NewReader("grace-pw\n")
	out, err := kinit.CombinedOutput()
	require.NoError(t, err, "%s", out)

	mit := filepath.Join(tmp, "armor-mit")
	kinit = exec.Command(filepath.Join(bin, "kinit"), "-k", "-t", filepath.Join(dir, "fast.keytab"), "-c", mit, "host/fast.f.test@F.TEST")
	kinit.Env = append(os.Environ(), "KRB5_CONFIG="+filepath.Join(dir, "krb5.conf"))
	out, err = kinit.CombinedOutput()
	require.NoError(t, err, "%s", out)

	cc, err := credentials.LoadCCache(mit)
	require.NoError(t, err)

	armor, err := client.ArmorFromCCache(cc, "F.TEST")
	require.NoError(t, err)

	cl := client.NewWithPassword("grace", "F.TEST", "grace-pw", cfg, client.FASTArmor(armor))
	require.NoError(t, cl.Login())
}

package examples_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/test"
)

// runner runs the examples, built once, against one krb5.conf.
type runner struct {
	t    *testing.T
	bin  string
	conf string
}

func newRunner(t *testing.T, conf string) *runner {
	t.Helper()

	bin := t.TempDir()
	out, err := exec.Command("go", "build", "-o", bin+string(filepath.Separator), "./...").CombinedOutput()
	require.NoError(t, err, string(out))

	return &runner{t: t, bin: bin, conf: conf}
}

func (r *runner) cmd(ctx context.Context, name, stdin string, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, filepath.Join(r.bin, name), args...)
	c.Env = append(os.Environ(), "KRB5_CONFIG="+r.conf)
	c.Stdin = strings.NewReader(stdin)

	return c
}

// run runs an example to its end and returns what it printed; it must succeed.
func (r *runner) run(name, stdin string, args ...string) string {
	r.t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	out, err := r.cmd(ctx, name, stdin, args...).CombinedOutput()
	require.NoError(r.t, err, "%s: %s", name, out)

	return string(out)
}

// serve starts a server example and returns the address it listens on.
func (r *runner) serve(name string, args func(addr string) []string) string {
	r.t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(r.t, err)

	addr := l.Addr().String()
	require.NoError(r.t, l.Close())

	ctx, cancel := context.WithCancel(context.Background())

	c := r.cmd(ctx, name, "", args(addr)...)
	stderr, err := c.StderrPipe()
	require.NoError(r.t, err)
	require.NoError(r.t, c.Start())

	r.t.Cleanup(func() {
		cancel()

		_ = c.Wait()
	})

	// Its log goes on being read, or it would block on a full pipe.
	listening := make(chan struct{})

	go func() {
		s := bufio.NewScanner(stderr)
		for s.Scan() {
			if strings.Contains(s.Text(), "listening on") {
				close(listening)
			}
		}
	}()

	select {
	case <-listening:
	case <-time.After(30 * time.Second):
		r.t.Fatalf("%s did not start", name)
	}

	return addr
}

// The examples against MIT's KDCs (test/mitkdc).
func TestExamples_MIT(t *testing.T) {
	dir := test.MIT(t)
	r := newRunner(t, filepath.Join(dir, "krb5.conf"))
	path := func(name string) string { return filepath.Join(dir, name) }

	assert.Contains(t, r.run("tgt-password", "alice-pw\n", "-user", "alice", "-realm", "A.TEST"), "TGT krbtgt/A.TEST for alice@A.TEST")
	assert.Contains(t, r.run("tgt-password", "alice-pw\n", "-user", "alice"), "alice@A.TEST", "the default realm")
	assert.Contains(t, r.run("tgt-keytab", "", "-keytab", path("svc.keytab"), "-principal", "HTTP/svc.a.test", "-realm", "A.TEST"),
		"for HTTP/svc.a.test@A.TEST")

	assert.Contains(t, r.run("service-ticket", "alice-pw\n", "-user", "alice", "-spn", "HTTP/svc.a.test"), "ticket to HTTP/svc.a.test@A.TEST")
	assert.Contains(t, r.run("service-ticket", "", "-user", "HTTP/svc.a.test", "-realm", "A.TEST", "-keytab", path("svc.keytab"), "-spn", "host/svc.a.test"),
		"ticket to host/svc.a.test@A.TEST")

	cc := filepath.Join(t.TempDir(), "alice.cc")
	assert.Contains(t, r.run("ccache", "alice-pw\n", "-user", "alice", "-path", cc, "-spn", "HTTP/svc.a.test"), "a ticket to HTTP/svc.a.test")
	assert.Contains(t, r.run("service-ticket", "", "-ccache", cc, "-spn", "host/svc.a.test"), "ticket to host/svc.a.test@A.TEST")

	klist, err := exec.Command(filepath.Join(test.MITBin(t), "klist"), "-c", cc).CombinedOutput()
	require.NoError(t, err, string(klist))
	assert.Contains(t, string(klist), "HTTP/svc.a.test@A.TEST", "the cache as MIT reads it")

	out := r.run("cross-realm", "alice-pw\n", "-user", "alice", "-realm", "A.TEST", "-spn", "HTTP/svc.b.test", "-keytab", path("b.keytab"))
	assert.Contains(t, out, "ticket to HTTP/svc.b.test@B.TEST")
	assert.Contains(t, out, "holds krbtgt/B.TEST@A.TEST")
	assert.Contains(t, out, "the service sees alice@A.TEST")

	// The other way across the trust.
	out = r.run("cross-realm", "bea-pw\n", "-user", "bea", "-realm", "B.TEST", "-spn", "HTTP/svc.a.test", "-keytab", path("svc.keytab"))
	assert.Contains(t, out, "the service sees bea@B.TEST")

	assert.Contains(t, r.run("impersonate", "", "-keytab", path("s4u.keytab"), "-service", "HTTP/proxy.a.test", "-realm", "A.TEST", "-user", "alice"),
		"in the name of alice@A.TEST, forwardable: true")

	addr := r.serve("spnego-server", func(a string) []string { return []string{"-keytab", path("svc.keytab"), "-addr", a} })
	assert.Contains(t, r.run("spnego-client", "alice-pw\n", "-user", "alice", "-spn", "HTTP/svc.a.test", "-url", "http://"+addr+"/"), "hello alice@A.TEST")

	addr = r.serve("gss-echo", func(a string) []string { return []string{"-listen", a, "-keytab", path("svc.keytab")} })
	assert.Contains(t, r.run("gss-echo", "alice-pw\n", "-connect", addr, "-user", "alice", "-spn", "host/svc.a.test", "-message", "hi"),
		"echo: hi (encrypted: true)")

	assert.Contains(t, r.run("fast", "grace-pw\n", "-user", "grace", "-realm", "F.TEST", "-armor-keytab", path("fast.keytab"),
		"-armor-principal", "host/fast.f.test", "-spn", "HTTP/svc.f.test"), "a ticket to HTTP/svc.f.test")

	pki := path("pki")
	assert.Contains(t, r.run("pkinit", "", "-user", "pat", "-realm", "P.TEST", "-identity", "FILE:"+pki+"/pat.pem,"+pki+"/pat.key"), "TGT for pat@P.TEST")
	assert.Contains(t, r.run("pkinit", "", "-anonymous", "-realm", "P.TEST"), "WELLKNOWN/ANONYMOUS")

	// A keytab made from a password logs in.
	kt := filepath.Join(t.TempDir(), "alice.keytab")
	r.run("keytab-make", "alice-pw\n", "-principal", "alice", "-realm", "A.TEST", "-out", kt)

	info, err := os.Stat(kt)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	assert.Contains(t, r.run("tgt-keytab", "", "-keytab", kt, "-principal", "alice", "-realm", "A.TEST"), "for alice@A.TEST")
}

var kvnoRe = regexp.MustCompile(`kvno (\d+)`)

// The examples against a live AD (test/ad). KCD is the one MIT cannot do.
func TestExamples_AD(t *testing.T) {
	dir, password := test.ADLive(t)
	r := newRunner(t, filepath.Join(dir, "krb5.conf"))
	stdin := password + "\n"

	const realm = "GOOSE.TEST"

	assert.Contains(t, r.run("tgt-password", stdin, "-user", "alice", "-realm", realm), "alice@GOOSE.TEST")

	// A keytab for an account: its kvno, from a ticket to it.
	keytabFor := func(account, spn string) string {
		m := kvnoRe.FindStringSubmatch(r.run("service-ticket", stdin, "-user", "alice", "-realm", realm, "-spn", spn))
		require.NotNil(t, m)

		kvno, err := strconv.Atoi(m[1])
		require.NoError(t, err)

		kt := filepath.Join(t.TempDir(), account+".keytab")
		r.run("keytab-make", stdin, "-principal", account, "-realm", realm, "-kvno", fmt.Sprint(kvno), "-out", kt)

		return kt
	}

	proxy := keytabFor("svc-proxy", "HTTP/proxy.goose.test")
	target := keytabFor("svc-target", "HTTP/target.goose.test")

	assert.Contains(t, r.run("tgt-keytab", "", "-keytab", proxy, "-principal", "svc-proxy", "-realm", realm), "for svc-proxy@GOOSE.TEST")

	out := r.run("impersonate", "", "-keytab", proxy, "-service", "svc-proxy", "-realm", realm, "-user", "alice")
	assert.Contains(t, out, "in the name of alice@GOOSE.TEST, forwardable: true")
	assert.Contains(t, out, "PAC user: alice")

	// The whole of KCD: the back end sees alice, from the front end's call.
	addr := r.serve("spnego-server", func(a string) []string {
		return []string{"-keytab", target, "-addr", a, "-principal", "svc-target"}
	})

	out = r.run("kcd", "", "-keytab", proxy, "-service", "svc-proxy", "-realm", realm, "-user", "alice",
		"-target", "HTTP/target.goose.test", "-url", "http://"+addr+"/")
	assert.Contains(t, out, "200 OK")
	assert.Contains(t, out, "hello alice@GOOSE.TEST")
	assert.Contains(t, out, "logon domain GOOSE")

	// And a user going straight to the service's own keytab, with its PAC.
	web := filepath.Join(dir, "web.keytab")
	addr = r.serve("spnego-server", func(a string) []string { return []string{"-keytab", web, "-addr", a} })
	assert.Contains(t, r.run("spnego-client", stdin, "-user", "alice", "-realm", realm, "-spn", "HTTP/web.goose.test", "-url", "http://"+addr+"/"),
		"hello alice@GOOSE.TEST")

	if ldapAddr, host := os.Getenv("TEST_AD_LDAP"), os.Getenv("TEST_AD_DC_HOST"); ldapAddr != "" && host != "" {
		out = r.run("ldap-whoami", stdin, "-user", "alice", "-realm", realm, "-ldap", ldapAddr, "-dc", host)
		assert.Contains(t, out, "alice")
		assert.Contains(t, out, "GooseTesters")
	}
}

package spnego_test

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/gsskrb5"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/service"
	"github.com/go-krb5/krb5/spnego"
	"github.com/go-krb5/krb5/test"
)

// MIT's gss-sample wire protocol (appl/gss-sample): a flags byte, a 4-byte
// length, the token.
const (
	tokNoop        = 1
	tokContext     = 2
	tokData        = 4
	tokMIC         = 8
	tokContextNext = 16
	tokWrapped     = 32
	tokSendMIC     = 128
)

func sendTok(t *testing.T, w io.Writer, f byte, tok []byte) {
	t.Helper()

	h := []byte{f, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(h[1:], uint32(len(tok)))
	_, err := w.Write(append(h, tok...))
	require.NoError(t, err)
}

func recvTok(t *testing.T, r io.Reader) (byte, []byte) {
	t.Helper()

	h := make([]byte, 5)
	_, err := io.ReadFull(r, h)
	require.NoError(t, err)

	tok := make([]byte, binary.BigEndian.Uint32(h[1:]))
	_, err = io.ReadFull(r, tok)
	require.NoError(t, err)

	return h[0], tok
}

type mitSPNEGO struct {
	dir, bin string
	cfg      *config.Config
	kt       *keytab.Keytab
}

func newMITSPNEGO(t *testing.T) mitSPNEGO {
	dir := test.MIT(t)
	bin := test.MITBin(t)

	cfg, err := config.Load(filepath.Join(dir, "krb5.conf"))
	require.NoError(t, err)

	kt, err := keytab.Load(filepath.Join(dir, "svc.keytab"))
	require.NoError(t, err)

	return mitSPNEGO{dir: dir, bin: bin, cfg: cfg, kt: kt}
}

func (m mitSPNEGO) env(cache string) []string {
	return append(os.Environ(), "KRB5_CONFIG="+filepath.Join(m.dir, "krb5.conf"), "KRB5CCNAME=FILE:"+cache,
		"KRB5_KTNAME=FILE:"+filepath.Join(m.dir, "svc.keytab"))
}

// kinit alice into a fresh cache and return its environment.
func (m mitSPNEGO) kinitAlice(t *testing.T) []string {
	t.Helper()

	cache := filepath.Join(t.TempDir(), "cc")
	env := m.env(cache)

	kinit := exec.Command(filepath.Join(m.bin, "kinit"), "-f", "alice")
	kinit.Env = env
	kinit.Stdin = strings.NewReader("alice-pw\n")

	out, err := kinit.CombinedOutput()
	require.NoError(t, err, string(out))

	return env
}

// gssServer runs MIT's gss-server -inetd on one connection to 127.0.0.1 (it
// accepts a SPNEGO initiator without a -spnego flag) and returns the other
// end and the server's log.
func (m mitSPNEGO) gssServer(t *testing.T) (net.Conn, func() string) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer l.Close()

	c, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)

	s, err := l.Accept()
	require.NoError(t, err)

	f, err := s.(*net.TCPConn).File()
	require.NoError(t, err)
	s.Close()

	log := filepath.Join(t.TempDir(), "gss-server.log")
	cmd := exec.Command(filepath.Join(m.bin, "..", "sbin", "gss-server"), "-inetd", "-export", "-logfile", log,
		"-keytab", filepath.Join(m.dir, "svc.keytab"), "host@svc.a.test")
	cmd.Env = m.env(filepath.Join(t.TempDir(), "unused"))
	cmd.Stdin, cmd.Stdout = f, f
	require.NoError(t, cmd.Start())
	f.Close()

	t.Cleanup(func() {
		c.Close()
		_ = cmd.Wait()
	})

	return c, func() string {
		b, _ := os.ReadFile(log)
		return string(b)
	}
}

// Our SPNEGO initiator to MIT's gss-server, with and without mutual
// authentication: the negotiation completes, then a wrapped message the
// server unwraps and answers with a MIC we verify.
func TestInitiator_MITServer_SPNEGO(t *testing.T) {
	m := newMITSPNEGO(t)

	for _, tc := range []struct {
		name string
		opts spnego.InitOptions
	}{
		{"mutual", spnego.InitOptions{Flags: gsskrb5.FlagMutual}},
		{"no mutual", spnego.InitOptions{}},
		{"mutual, delegation", spnego.InitOptions{Flags: gsskrb5.FlagMutual, Delegate: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cl := client.NewWithPassword("alice", "A.TEST", "alice-pw", m.cfg)
			require.NoError(t, cl.Login())

			c, log := m.gssServer(t)

			ctx, tok, err := spnego.NewInitiator(cl, "host/svc.a.test", tc.opts)
			require.NoError(t, err)

			sendTok(t, c, tokNoop|tokContextNext, nil)
			sendTok(t, c, tokContext, tok)

			// A SPNEGO acceptor always answers with a NegTokenResp.
			f, rep := recvTok(t, c)
			require.Equal(t, byte(tokContext), f, log())

			out, err := ctx.Continue(rep)
			require.NoError(t, err, log())
			require.Nil(t, out, "no mechListMIC leg is owed for a lone Kerberos offer")
			require.True(t, ctx.Established(), log())

			w, err := ctx.GSS().Wrap([]byte("hello from go"), true)
			require.NoError(t, err)

			sendTok(t, c, tokData|tokWrapped|tokSendMIC|tokMIC|64, w) // 64 = encrypted

			f, mic := recvTok(t, c)
			require.Equal(t, byte(tokMIC), f, log())
			require.NoError(t, ctx.GSS().VerifyMIC([]byte("hello from go"), mic))

			sendTok(t, c, tokNoop, nil)
			c.Close()

			time.Sleep(100 * time.Millisecond)
			assert.Contains(t, log(), `Received message: "hello from go"`, log())
		})
	}
}

// serveSPNEGO is our acceptor in gss-sample's protocol for one connection: it
// completes the negotiation, then unwraps messages and answers their MICs.
func serveSPNEGO(t *testing.T, c net.Conn, s *service.Settings) (*spnego.Context, []string, error) {
	t.Helper()

	f, _ := recvTok(t, c)
	if f != tokNoop|tokContextNext {
		return nil, nil, fmt.Errorf("first token flags %#x", f)
	}

	f, tok := recvTok(t, c)
	if f != tokContext {
		return nil, nil, fmt.Errorf("context token flags %#x", f)
	}

	ctx, out, err := spnego.Accept(tok, s, spnego.AcceptOptions{})
	if out != nil {
		sendTok(t, c, tokContext, out)
	}

	if err != nil {
		return nil, nil, err
	}

	var msgs []string

	for {
		f, tok := recvTok(t, c)
		if f&tokNoop != 0 {
			return ctx, msgs, nil
		}

		msg := tok
		if f&tokWrapped != 0 {
			msg, _, err = ctx.GSS().Unwrap(tok)
			if err != nil {
				return ctx, msgs, err
			}
		}

		msgs = append(msgs, string(msg))

		if f&tokSendMIC != 0 {
			mic, err := ctx.GSS().GetMIC(msg)
			if err != nil {
				return ctx, msgs, err
			}

			sendTok(t, c, tokMIC, mic)
		} else {
			sendTok(t, c, tokNoop, nil)
		}
	}
}

// MIT's gss-client -spnego to our SPNEGO acceptor: the negotiation completes
// (mutual or not), the message is unwrapped, and MIT verifies our MIC
// ("Signature verified.").
func TestMITClient_Acceptor_SPNEGO(t *testing.T) {
	m := newMITSPNEGO(t)
	env := m.kinitAlice(t)

	for _, opts := range [][]string{{"-spnego"}, {"-spnego", "-nomutual"}} {
		t.Run(strings.Join(opts, " "), func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)

			defer l.Close()

			port := l.Addr().(*net.TCPAddr).Port
			args := append([]string{"-port", fmt.Sprint(port)}, opts...)
			args = append(args, "127.0.0.1", "host@svc.a.test", "hello goose")

			cmd := exec.Command(filepath.Join(m.bin, "gss-client"), args...)
			cmd.Env = env

			done := make(chan []byte, 1)
			go func() { o, _ := cmd.CombinedOutput(); done <- o }()

			c, err := l.Accept()
			require.NoError(t, err)

			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(20 * time.Second))

			s := service.NewSettings(m.kt, service.DecodePAC(false))
			ctx, msgs, err := serveSPNEGO(t, c, s)

			o := <-done
			require.NoError(t, err, string(o))
			assert.Contains(t, string(o), "Signature verified.", string(o))
			require.NotNil(t, ctx)
			assert.True(t, ctx.Established())
			assert.Equal(t, []string{"hello goose"}, msgs)
			assert.Equal(t, "alice", ctx.GSS().Credentials().UserName())
		})
	}
}

// Our initiator and acceptor together, through MIT's KDC: mutual
// authentication, the peer identity, and messages wrapped both ways.
func TestInitiatorAcceptor_SPNEGO(t *testing.T) {
	m := newMITSPNEGO(t)

	cl := client.NewWithPassword("alice", "A.TEST", "alice-pw", m.cfg)
	require.NoError(t, cl.Login())

	ic, tok, err := spnego.NewInitiator(cl, "host/svc.a.test", spnego.InitOptions{Flags: gsskrb5.FlagMutual})
	require.NoError(t, err)

	ac, out, err := spnego.Accept(tok, service.NewSettings(m.kt, service.DecodePAC(false)), spnego.AcceptOptions{})
	require.NoError(t, err)
	require.NotNil(t, out)
	require.True(t, ac.Established())
	assert.Equal(t, "alice", ac.GSS().Credentials().UserName())

	back, err := ic.Continue(out)
	require.NoError(t, err)
	require.Nil(t, back)
	require.True(t, ic.Established())

	w, err := ic.GSS().Wrap([]byte("to the acceptor"), true)
	require.NoError(t, err)

	msg, sealed, err := ac.GSS().Unwrap(w)
	require.NoError(t, err)
	assert.True(t, sealed)
	assert.Equal(t, "to the acceptor", string(msg))

	mic, err := ac.GSS().GetMIC([]byte("from the acceptor"))
	require.NoError(t, err)
	require.NoError(t, ic.GSS().VerifyMIC([]byte("from the acceptor"), mic))
}

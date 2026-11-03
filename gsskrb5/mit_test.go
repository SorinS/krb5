package gsskrb5_test

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
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/service"
	"github.com/go-krb5/krb5/test"
	"github.com/go-krb5/krb5/types"
)

// MIT's gss-sample protocol (appl/gss-sample): a flags byte, a 4-byte
// length, the token.
const (
	tokenNoop        = 1
	tokenContext     = 2
	tokenData        = 4
	tokenMIC         = 8
	tokenContextNext = 16
	tokenWrapped     = 32
	tokenEncrypted   = 64
	tokenSendMIC     = 128
)

func sendToken(t *testing.T, w io.Writer, f byte, tok []byte) {
	t.Helper()

	h := []byte{f, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(h[1:], uint32(len(tok)))
	_, err := w.Write(append(h, tok...))
	require.NoError(t, err)
}

func recvToken(t *testing.T, r io.Reader) (byte, []byte) {
	t.Helper()

	h := make([]byte, 5)
	_, err := io.ReadFull(r, h)
	require.NoError(t, err)

	tok := make([]byte, binary.BigEndian.Uint32(h[1:]))
	_, err = io.ReadFull(r, tok)
	require.NoError(t, err)

	return h[0], tok
}

type mit struct {
	dir, bin string
	cfg      *config.Config
	kt       *keytab.Keytab
}

func newMIT(t *testing.T) mit {
	dir := test.MIT(t)
	bin := test.MITBin(t)

	cfg, err := config.Load(filepath.Join(dir, "krb5.conf"))
	require.NoError(t, err)

	kt, err := keytab.Load(filepath.Join(dir, "svc.keytab"))
	require.NoError(t, err)

	return mit{dir: dir, bin: bin, cfg: cfg, kt: kt}
}

func (m mit) env(cache string) []string {
	return append(os.Environ(), "KRB5_CONFIG="+filepath.Join(m.dir, "krb5.conf"), "KRB5CCNAME=FILE:"+cache,
		"KRB5_KTNAME=FILE:"+filepath.Join(m.dir, "svc.keytab"))
}

// gssServer runs MIT's gss-server -inetd on one connection to 127.0.0.1,
// and returns the connection's other end and the server's log.
func (m mit) gssServer(t *testing.T) (net.Conn, func() string) {
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
	cmd := exec.Command(filepath.Join(m.bin, "..", "sbin", "gss-server"), "-inetd", "-logfile", log, "-keytab",
		filepath.Join(m.dir, "svc.keytab"), "host@svc.a.test")
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

// Our initiator to MIT's acceptor: a context (mutual, with delegation or
// not, with sequencing), a message wrapped with confidentiality or not,
// which gss-server unwraps and answers with a MIC, which we check.
func TestInitiator_MITServer(t *testing.T) {
	m := newMIT(t)

	for _, tc := range []struct {
		name string
		opts gsskrb5.InitOptions
		conf bool
	}{
		{"mutual, sealed", gsskrb5.InitOptions{Flags: gsskrb5.FlagMutual}, true},
		{"mutual, integrity only", gsskrb5.InitOptions{Flags: gsskrb5.FlagMutual}, false},
		{"mutual, sequence, replay", gsskrb5.InitOptions{Flags: gsskrb5.FlagMutual | gsskrb5.FlagSequence | gsskrb5.FlagReplay}, true},
		{"mutual, delegation", gsskrb5.InitOptions{Flags: gsskrb5.FlagMutual, Delegate: true}, true},
		{"no mutual", gsskrb5.InitOptions{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cl := client.NewWithPassword("alice", "A.TEST", "alice-pw", m.cfg)
			require.NoError(t, cl.Login())

			c, log := m.gssServer(t)

			ctx, tok, err := gsskrb5.NewInitiator(cl, "host/svc.a.test", tc.opts)
			require.NoError(t, err)

			sendToken(t, c, tokenNoop|tokenContextNext, nil)
			sendToken(t, c, tokenContext, tok)

			if tc.opts.Flags&gsskrb5.FlagMutual != 0 {
				f, rep := recvToken(t, c)
				require.Equal(t, byte(tokenContext), f, log())
				require.NoError(t, ctx.Continue(rep), log())
			}

			require.True(t, ctx.Established())

			for i, msg := range []string{"hello from go", "and again"} {
				w, err := ctx.Wrap([]byte(msg), tc.conf)
				require.NoError(t, err)

				fl := byte(tokenData | tokenWrapped | tokenSendMIC)
				if tc.conf {
					fl |= tokenEncrypted
				}

				sendToken(t, c, fl, w)

				f, mic := recvToken(t, c)
				require.Equal(t, byte(tokenMIC), f, "message %d: %s", i, log())
				require.NoError(t, ctx.VerifyMIC([]byte(msg), mic), "message %d", i)
			}

			sendToken(t, c, tokenNoop, nil)
			c.Close()

			time.Sleep(100 * time.Millisecond)

			l := log()
			assert.Contains(t, l, "Received message: \"hello from go\"", l)
			assert.Contains(t, l, "Received message: \"and again\"", l)
			assert.Equal(t, tc.opts.Flags&gsskrb5.FlagSequence != 0, strings.Contains(l, "GSS_C_SEQUENCE_FLAG"), l)
			assert.Equal(t, tc.opts.Delegate, strings.Contains(l, "GSS_C_DELEG_FLAG"), l)
		})
	}
}

// serveOne is our acceptor in gss-sample's protocol, for one connection:
// it returns the context and the messages it unwrapped.
func serveOne(t *testing.T, c net.Conn, s *service.Settings) (*gsskrb5.Context, []string, error) {
	f, _ := recvToken(t, c)
	if f != tokenNoop|tokenContextNext {
		return nil, nil, fmt.Errorf("first token flags %#x", f)
	}

	f, tok := recvToken(t, c)
	if f != tokenContext {
		return nil, nil, fmt.Errorf("context token flags %#x", f)
	}

	ctx, out, err := gsskrb5.Accept(tok, s, gsskrb5.AcceptOptions{})
	if out != nil {
		sendToken(t, c, tokenContext, out)
	}

	if err != nil {
		return nil, nil, err
	}

	var msgs []string

	for {
		f, tok := recvToken(t, c)
		if f&tokenNoop != 0 {
			return ctx, msgs, nil
		}

		msg := tok
		if f&tokenWrapped != 0 {
			var sealed bool

			msg, sealed, err = ctx.Unwrap(tok)
			if err != nil {
				return ctx, msgs, err
			}

			if sealed != (f&tokenEncrypted != 0) {
				return ctx, msgs, fmt.Errorf("sealed %v, the client said %#x", sealed, f)
			}
		}

		msgs = append(msgs, string(msg))

		if f&tokenSendMIC != 0 {
			mic, err := ctx.GetMIC(msg)
			if err != nil {
				return ctx, msgs, err
			}

			sendToken(t, c, tokenMIC, mic)
		} else {
			sendToken(t, c, tokenNoop, nil)
		}
	}
}

// MIT's gss-client to our acceptor: its options for mutual or not,
// delegation, sequencing, wrap without confidentiality; it checks our MIC
// ("Signature verified."). A delegated TGT gets a service ticket.
func TestMITClient_Acceptor(t *testing.T) {
	m := newMIT(t)

	cache := filepath.Join(t.TempDir(), "cc")
	kinit := exec.Command(filepath.Join(m.bin, "kinit"), "-f", "alice")
	kinit.Env = m.env(cache)
	kinit.Stdin = strings.NewReader("alice-pw\n")
	out, err := kinit.CombinedOutput()
	require.NoError(t, err, string(out))

	for _, opts := range [][]string{nil, {"-nx"}, {"-nomutual"}, {"-seq"}, {"-d"}, {"-d", "-seq", "-nx"}, {"-mcount", "3"}} {
		t.Run(strings.Join(append([]string{"gss-client"}, opts...), " "), func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)

			defer l.Close()

			port := l.Addr().(*net.TCPAddr).Port
			args := append([]string{"-port", fmt.Sprint(port)}, opts...)
			args = append(args, "127.0.0.1", "host@svc.a.test", "hello goose")

			cmd := exec.Command(filepath.Join(m.bin, "gss-client"), args...)
			cmd.Env = m.env(cache)

			done := make(chan []byte, 1)
			go func() {
				o, _ := cmd.CombinedOutput()
				done <- o
			}()

			c, err := l.Accept()
			require.NoError(t, err)

			defer c.Close()

			_ = c.SetDeadline(time.Now().Add(20 * time.Second))

			s := service.NewSettings(m.kt, service.DecodePAC(false))
			ctx, msgs, err := serveOne(t, c, s)

			o := <-done
			require.NoError(t, err, string(o))
			assert.Contains(t, string(o), "Signature verified.", string(o))
			assert.NotEmpty(t, msgs)

			for _, msg := range msgs {
				assert.Equal(t, "hello goose", msg)
			}

			assert.Equal(t, "alice", ctx.Credentials().UserName())

			deleg := ctx.Delegated()
			if strings.Contains(strings.Join(opts, " "), "-d") {
				require.NotNil(t, deleg, "delegated credentials")
				require.Equal(t, uint32(gsskrb5.FlagDeleg), ctx.Flags()&gsskrb5.FlagDeleg)

				tgts := deleg.GetEntries()
				require.Len(t, tgts, 1)
				assert.True(t, types.IsFlagSet(&tgts[0].TicketFlags, flags.Forwarded), "a forwarded TGT")

				// The delegated TGT works: a service ticket with it.
				cl, err := client.NewFromCCache(deleg, m.cfg)
				require.NoError(t, err)

				_, _, err = cl.GetServiceTicket("HTTP/svc.a.test")
				require.NoError(t, err)
			} else {
				assert.Nil(t, deleg)
			}
		})
	}
}

// Ours to ours, through MIT's KDC: delegation, then every token kind both
// ways, and a replayed or reordered token refused.
func TestInitiatorAcceptor(t *testing.T) {
	m := newMIT(t)

	cl := client.NewWithPassword("alice", "A.TEST", "alice-pw", m.cfg)
	require.NoError(t, cl.Login())

	ic, tok, err := gsskrb5.NewInitiator(cl, "host/svc.a.test", gsskrb5.InitOptions{
		Flags: gsskrb5.FlagMutual | gsskrb5.FlagSequence | gsskrb5.FlagReplay, Delegate: true,
		ChannelBindings: &gsskrb5.ChannelBindings{ApplicationData: []byte("tls-server-end-point:xyz")},
	})
	require.NoError(t, err)

	// Other channel bindings are refused, with an error token.
	_, out, err := gsskrb5.Accept(tok, service.NewSettings(m.kt, service.DecodePAC(false)),
		gsskrb5.AcceptOptions{ChannelBindings: &gsskrb5.ChannelBindings{ApplicationData: []byte("tls-server-end-point:abc")}})
	require.Error(t, err)
	require.NotNil(t, out)
	assert.Error(t, ic.Continue(out))

	ic, tok, err = gsskrb5.NewInitiator(cl, "host/svc.a.test", gsskrb5.InitOptions{
		Flags: gsskrb5.FlagMutual | gsskrb5.FlagSequence | gsskrb5.FlagReplay, Delegate: true,
		ChannelBindings: &gsskrb5.ChannelBindings{ApplicationData: []byte("tls-server-end-point:xyz")},
	})
	require.NoError(t, err)

	ac, out, err := gsskrb5.Accept(tok, service.NewSettings(m.kt, service.DecodePAC(false)),
		gsskrb5.AcceptOptions{ChannelBindings: &gsskrb5.ChannelBindings{ApplicationData: []byte("tls-server-end-point:xyz")}})
	require.NoError(t, err)
	require.NotNil(t, out)
	require.NoError(t, ic.Continue(out))
	require.NotNil(t, ac.Delegated())

	for _, conf := range []bool{true, false} {
		w, err := ic.Wrap([]byte("to the acceptor"), conf)
		require.NoError(t, err)

		msg, sealed, err := ac.Unwrap(w)
		require.NoError(t, err)
		assert.Equal(t, conf, sealed)
		assert.Equal(t, "to the acceptor", string(msg))

		_, _, err = ac.Unwrap(w)
		assert.ErrorIs(t, err, gsskrb5.ErrSequence, "a replayed token")

		mic, err := ac.GetMIC([]byte("from the acceptor"))
		require.NoError(t, err)
		require.NoError(t, ic.VerifyMIC([]byte("from the acceptor"), mic))
		assert.ErrorIs(t, ic.VerifyMIC([]byte("from the acceptor"), mic), gsskrb5.ErrSequence)
		assert.Error(t, ic.VerifyMIC([]byte("changed"), mic))

		// Our own token is not taken as the peer's.
		w2, err := ic.Wrap([]byte("x"), conf)
		require.NoError(t, err)

		_, _, err = ic.Unwrap(w2)
		assert.ErrorIs(t, err, gsskrb5.ErrToken)

		// The acceptor skipped w2: with FlagSequence, the next is out of order.
		w3, err := ic.Wrap([]byte("y"), conf)
		require.NoError(t, err)

		_, _, err = ac.Unwrap(w3)
		assert.ErrorIs(t, err, gsskrb5.ErrSequence)

		_, _, err = ac.Unwrap(w2)
		require.NoError(t, err)
		_, _, err = ac.Unwrap(w3)
		require.NoError(t, err)
	}
}

package ldap

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SorinS/krb5/client"
	"github.com/SorinS/krb5/config"
	"github.com/SorinS/krb5/gsskrb5"
	"github.com/SorinS/krb5/keytab"
	"github.com/SorinS/krb5/service"
	"github.com/SorinS/krb5/test"
)

// A server that binds the client with SASL GSSAPI (our acceptor, MIT's
// KDC) under the confidentiality layer, then answers Who am I? with its
// reply split across two wrapped buffers, and a second reply sharing a
// buffer with the end of the first: RFC 4752 allows both.
func TestSplitWrappedMessages_MIT(t *testing.T) {
	dir := test.MIT(t)

	cfg, err := config.Load(filepath.Join(dir, "krb5.conf"))
	require.NoError(t, err)

	kt, err := keytab.Load(filepath.Join(dir, "svc.keytab"))
	require.NoError(t, err)

	cl := client.NewWithPassword("alice", "A.TEST", "alice-pw", cfg)
	require.NoError(t, cl.Login())

	a, b := net.Pipe()
	defer a.Close()

	go func() {
		defer b.Close()

		r := bufio.NewReader(b)
		bindReply := func(id int64, code int64, creds []byte) {
			body := [][]byte{encInt(0x0a, code), encOctets(0x04, nil), encOctets(0x04, nil)}
			if creds != nil {
				body = append(body, encOctets(classContext|7, creds))
			}

			_, _ = b.Write(enc(0x30, encInt(0x02, id), enc(opBindResponse, body...)))
		}

		credsOf := func(m tlv) []byte {
			es, _ := elements(m.body)
			op, _ := elements(es[1].body)
			sasl, _ := elements(op[2].body)

			if len(sasl) < 2 {
				return nil
			}

			return sasl[1].body
		}

		m, _ := readMessage(r)
		ctx, rep, err := gsskrb5.Accept(credsOf(m), service.NewSettings(kt, service.DecodePAC(false)), gsskrb5.AcceptOptions{})
		if err != nil {
			return
		}

		bindReply(1, ResultSaslBindInProgress, rep)

		_, _ = readMessage(r)
		offer, _ := ctx.Wrap([]byte{gsskrb5.LayerConfidentiality, 0, 0x40, 0}, false)
		bindReply(2, ResultSaslBindInProgress, offer)

		_, _ = readMessage(r)
		bindReply(3, ResultSuccess, nil)

		// Who am I? (id 4), then a second (id 5): wrapped.
		readWrapped := func() {
			var n [4]byte
			_, _ = io.ReadFull(r, n[:])
			w := make([]byte, binary.BigEndian.Uint32(n[:]))
			_, _ = io.ReadFull(r, w)
		}
		send := func(p []byte) {
			w, _ := ctx.Wrap(p, true)
			h := make([]byte, 4)
			binary.BigEndian.PutUint32(h, uint32(len(w)))
			_, _ = b.Write(append(h, w...))
		}
		whoami := func(id int64, who string) []byte {
			return enc(0x30, encInt(0x02, id), enc(opExtendedResponse, encInt(0x0a, 0), encOctets(0x04, nil),
				encOctets(0x04, nil), encOctets(classContext|11, []byte(who))))
		}

		readWrapped()
		readWrapped()

		first, second := whoami(4, "u:A\\alice"), whoami(5, "u:A\\again")
		send(first[:5])                        // part of the first
		send(append(first[5:], second[:3]...)) // its rest, and the start of the second
		send(second[3:])                       // the rest of the second
	}()

	c := NewConn(a)
	require.NoError(t, c.BindGSSAPI(cl, "host@svc.a.test", gsskrb5.LayerConfidentiality))
	assert.Equal(t, byte(gsskrb5.LayerConfidentiality), c.Layer())

	// Both requests go out before the replies are read.
	c.mu.Lock()
	op := enc(opExtendedRequest, encOctets(classContext|0, []byte("1.3.6.1.4.1.4203.1.11.3")))
	require.NoError(t, c.write(enc(0x30, encInt(0x02, 4), op)))
	require.NoError(t, c.write(enc(0x30, encInt(0x02, 5), op)))
	c.id = 5

	for _, want := range []struct {
		id  int64
		who string
	}{{4, "u:A\\alice"}, {5, "u:A\\again"}} {
		id, o, err := c.read()
		require.NoError(t, err)
		assert.Equal(t, want.id, id)

		_, rest, err := decResult(o.body)
		require.NoError(t, err)
		assert.Equal(t, want.who, string(rest[0].body))
	}
	c.mu.Unlock()
}

package client

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SorinS/krb5/config"
)

// pipeDialer gives one end of a pipe, not a *net.TCPConn: as a proxy's
// Dialer would (upstream PR 547's case, which panicked).
type pipeDialer struct{ serve func(net.Conn) }

func (d pipeDialer) Dial(network, addr string) (net.Conn, error) {
	a, b := net.Pipe()
	go d.serve(b)

	return a, nil
}

func TestSendTCP_Dialers(t *testing.T) {
	t.Parallel()

	reply := func(header []byte, body []byte, slow bool) func(net.Conn) {
		return func(c net.Conn) {
			defer c.Close()

			req := make([]byte, 4)
			_, _ = c.Read(req)

			buf := make([]byte, binary.BigEndian.Uint32(req))
			_, _ = c.Read(buf)

			if slow {
				for _, b := range header {
					_, _ = c.Write([]byte{b})
					time.Sleep(time.Millisecond)
				}
			} else {
				_, _ = c.Write(header)
			}

			_, _ = c.Write(body)
		}
	}

	kdcs := map[int]string{1: "kdc.example:88"}

	// A whole reply, its length one byte at a time.
	r, err := dialSendTCP(pipeDialer{reply([]byte{0, 0, 0, 3}, []byte("abc"), true)}, kdcs, []byte("req"))
	require.NoError(t, err)
	assert.Equal(t, "abc", string(r))

	// A length of 4 GB, or with the reserved bit set, is refused, not allocated.
	for _, h := range [][]byte{{0xff, 0xff, 0xff, 0xff}, {0x80, 0, 0, 3}, {0x00, 0x40, 0x00, 0x01}} {
		_, err := dialSendTCP(pipeDialer{reply(h, []byte("abc"), false)}, kdcs, []byte("req"))
		assert.ErrorContains(t, err, "announces a reply", "%x", h)
	}

	// UDP over a Dialer's connection, too.
	r, err = dialSendUDP(pipeDialer{func(c net.Conn) {
		defer c.Close()

		buf := make([]byte, 100)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("udp reply"))
	}}, kdcs, []byte("req"))
	require.NoError(t, err)
	assert.Equal(t, "udp reply", string(r))
}

// An empty realm is the configuration's default realm.
func TestNewWithPassword_DefaultRealm(t *testing.T) {
	t.Parallel()

	cfg, err := config.NewFromString("[libdefaults]\n default_realm = A.TEST\n")
	require.NoError(t, err)

	assert.Equal(t, "A.TEST", NewWithPassword("alice", "", "pw", cfg).Credentials.Domain())
	assert.Equal(t, "B.TEST", NewWithPassword("alice", "B.TEST", "pw", cfg).Credentials.Domain())
	assert.Equal(t, "A.TEST", NewWithKeytab("alice", "", nil, cfg).Credentials.Domain())
}

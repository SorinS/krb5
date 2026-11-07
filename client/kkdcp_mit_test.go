package client_test

import (
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/test"
)

// proxyMessage is an independent decoding of [MS-KKDCP] KDC-PROXY-MESSAGE,
// so the test's proxy and the client's kkdcp.go agree on the wire format
// without sharing code.
type proxyMessage struct {
	Message       []byte `asn1:"explicit,tag:0"`
	TargetDomain  string `asn1:"general,optional,explicit,tag:1"`
	DCLocatorHint int    `asn1:"optional,explicit,tag:2"`
}

// relayToKDC writes framed (a TCP-framed Kerberos message) to the MIT KDC at
// addr and returns its reply, framed as the KDC sends it over TCP.
func relayToKDC(addr string, framed []byte) ([]byte, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}

	h := make([]byte, 4)
	if _, err := io.ReadFull(conn, h); err != nil {
		return nil, err
	}

	body := make([]byte, binary.BigEndian.Uint32(h))
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}

	return append(h, body...), nil
}

// KKDCP against MIT's A.TEST (test/mitkdc): a local HTTPS proxy wraps and
// unwraps KDC-PROXY-MESSAGE and relays to the real KDC over TCP, so both an
// AS exchange (Login) and a TGS exchange (GetServiceTicket) go end to end
// over MS-KKDCP. The client trusts the proxy only through the realm's
// http_anchors.
func TestClient_KKDCP_MIT(t *testing.T) {
	dir := test.MIT(t)
	cfg := mitConfig(t, dir)

	// The real A.TEST KDC address, before it is replaced with the proxy URL.
	var kdcAddr string

	for i := range cfg.Realms {
		if cfg.Realms[i].Realm == "A.TEST" {
			require.NotEmpty(t, cfg.Realms[i].KDC, "A.TEST has a KDC in the harness config")
			kdcAddr = cfg.Realms[i].KDC[0]
		}
	}

	require.NotEmpty(t, kdcAddr)

	var hits int32

	proxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)

		if ct := r.Header.Get("Content-Type"); ct != "application/kerberos" {
			http.Error(w, "bad content type "+ct, http.StatusUnsupportedMediaType)

			return
		}

		in, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)

			return
		}

		var pm proxyMessage
		if _, err := asn1.Unmarshal(in, &pm, asn1.WithUnmarshalAllowTypeGeneralString(true)); err != nil {
			http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)

			return
		}

		if pm.TargetDomain != "A.TEST" {
			http.Error(w, "unexpected target-domain "+pm.TargetDomain, http.StatusBadRequest)

			return
		}

		reply, err := relayToKDC(kdcAddr, pm.Message)
		if err != nil {
			http.Error(w, "relay: "+err.Error(), http.StatusBadGateway)

			return
		}

		out, err := asn1.Marshal(proxyMessage{Message: reply})
		if err != nil {
			http.Error(w, "encode: "+err.Error(), http.StatusInternalServerError)

			return
		}

		w.Header().Set("Content-Type", "application/kerberos")
		_, _ = w.Write(out)
	}))
	defer proxy.Close()

	// Trust the proxy's certificate through the realm's http_anchors.
	pemPath := filepath.Join(t.TempDir(), "proxy-ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxy.Certificate().Raw})
	require.NoError(t, os.WriteFile(pemPath, certPEM, 0o600))

	for i := range cfg.Realms {
		if cfg.Realms[i].Realm == "A.TEST" {
			cfg.Realms[i].KDC = []string{proxy.URL}

			if cfg.Realms[i].Values == nil {
				cfg.Realms[i].Values = map[string][]string{}
			}

			cfg.Realms[i].Values["http_anchors"] = []string{"FILE:" + pemPath}
		}
	}

	// AS exchange over KKDCP.
	cl := client.NewWithPassword("alice", "A.TEST", "alice-pw", cfg)
	require.NoError(t, cl.Login(), "AS exchange through the KDC proxy")

	// TGS exchange over KKDCP.
	tkt, key, err := cl.GetServiceTicket("HTTP/svc.a.test")
	require.NoError(t, err, "TGS exchange through the KDC proxy")
	require.NotEmpty(t, key.KeyValue)
	assert.Equal(t, "HTTP/svc.a.test", tkt.SName.PrincipalNameString())

	assert.GreaterOrEqual(t, atomic.LoadInt32(&hits), int32(2), "AS and TGS both went through the proxy")

	// A wrong trust anchor must fail closed (the proxy's cert is not trusted).
	bad := mitConfig(t, dir)

	for i := range bad.Realms {
		if bad.Realms[i].Realm == "A.TEST" {
			bad.Realms[i].KDC = []string{proxy.URL}
		}
	}

	cl2 := client.NewWithPassword("alice", "A.TEST", "alice-pw", bad)
	require.Error(t, cl2.Login(), "an untrusted proxy certificate must not be accepted")
}

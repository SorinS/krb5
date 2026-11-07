package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-krb5/x/encoding/asn1"
)

// MS-KKDCP (the Kerberos KDC Proxy Protocol): Kerberos over HTTPS. A KDC
// written in krb5.conf as an https:// URL (e.g.
// `kdc = https://proxy.example.com/KdcProxy`) is a proxy rather than a KDC on
// 88: the TCP-framed Kerberos message is wrapped in a KDC-PROXY-MESSAGE and
// POSTed to the URL, and the KDC's reply comes back wrapped the same way. The
// realm's `http_anchors` relation (MIT's, `FILE:` entries) gives the CA roots
// to trust for the proxy's certificate; with none, the system roots are used.

// kkdcpContentType is the media type [MS-KKDCP] 2.2.1 requires on the POST.
const kkdcpContentType = "application/kerberos"

// kdcProxyMessage is [MS-KKDCP] 2.2.2 KDC-PROXY-MESSAGE. kerb-message is the
// Kerberos message framed as over TCP (a 4-byte big-endian length, then the
// message); target-domain is the realm. dclocator-hint is not sent.
type kdcProxyMessage struct {
	Message       []byte `asn1:"explicit,tag:0"`
	TargetDomain  string `asn1:"general,optional,explicit,tag:1"`
	DCLocatorHint int    `asn1:"optional,explicit,tag:2"`
}

// isKDCProxy reports whether a KDC entry (as GetKDCs returns it) is a proxy
// URL rather than a host:port.
func isKDCProxy(host string) bool {
	return strings.HasPrefix(strings.ToLower(host), "https://")
}

// usesKDCProxy reports whether the realm's KDCs are reached through an HTTPS
// proxy, so the request goes over KKDCP instead of UDP/TCP.
func (cl *Client) usesKDCProxy(realm string) bool {
	_, kdcs, err := cl.Config.GetKDCs(realm, true)
	if err != nil {
		return false
	}

	for _, h := range kdcs {
		if isKDCProxy(h) {
			return true
		}
	}

	return false
}

// sendKDCProxy sends the request b (unframed) to the realm's HTTPS KDC proxy
// and returns the KDC's reply, a KRBError among them, as the TCP path does.
func (cl *Client) sendKDCProxy(realm string, b []byte) ([]byte, error) {
	_, kdcs, err := cl.Config.GetKDCs(realm, true)
	if err != nil {
		return nil, err
	}

	framed := make([]byte, 4, 4+len(b))
	binary.BigEndian.PutUint32(framed, uint32(len(b)))
	framed = append(framed, b...)

	msg, err := asn1.Marshal(kdcProxyMessage{Message: framed, TargetDomain: realm})
	if err != nil {
		return nil, fmt.Errorf("KKDCP: marshaling KDC-PROXY-MESSAGE: %w", err)
	}

	hc, err := cl.kkdcpHTTPClient(realm)
	if err != nil {
		return nil, err
	}

	var errs []string

	for i := 1; i <= len(kdcs); i++ {
		if !isKDCProxy(kdcs[i]) {
			continue
		}

		rb, err := postKDCProxy(hc, kdcs[i], msg)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", kdcs[i], err))

			continue
		}

		return checkForKRBError(rb)
	}

	if len(errs) == 0 {
		return nil, fmt.Errorf("KKDCP: no https KDC proxy configured for realm %s", realm)
	}

	return nil, fmt.Errorf("KKDCP: sending to a KDC proxy: %s", strings.Join(errs, "; "))
}

// postKDCProxy POSTs a marshaled KDC-PROXY-MESSAGE to the proxy at rawURL and
// returns the KDC's reply, unframed (the 4-byte length stripped).
func postKDCProxy(hc *http.Client, rawURL string, msg []byte) ([]byte, error) {
	resp, err := hc.Post(rawURL, kkdcpContentType, bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy returned %s", resp.Status)
	}

	// The length prefix bounds the body as over TCP; a little slack for the
	// KDC-PROXY-MESSAGE wrapping.
	rb, err := io.ReadAll(io.LimitReader(resp.Body, maxTCPReply+1024))
	if err != nil {
		return nil, fmt.Errorf("reading the proxy's reply: %w", err)
	}

	var pm kdcProxyMessage
	if _, err := asn1.Unmarshal(rb, &pm, asn1.WithUnmarshalAllowTypeGeneralString(true)); err != nil {
		return nil, fmt.Errorf("decoding the proxy's KDC-PROXY-MESSAGE: %w", err)
	}

	if len(pm.Message) < 4 {
		return nil, fmt.Errorf("the proxy's reply is %d bytes, too short to be framed", len(pm.Message))
	}

	n := binary.BigEndian.Uint32(pm.Message[:4])
	if int64(n) != int64(len(pm.Message)-4) {
		return nil, fmt.Errorf("the proxy's reply announces %d bytes but carries %d", n, len(pm.Message)-4)
	}

	return pm.Message[4:], nil
}

// kkdcpHTTPClient is the HTTPS client for the realm's proxy: the realm's
// http_anchors as the trusted roots (system roots with none), and the
// client's Dialer for the connection (a proxy's, say).
func (cl *Client) kkdcpHTTPClient(realm string) (*http.Client, error) {
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}

	anchors := cl.httpAnchors(realm)
	if len(anchors) > 0 {
		pool := x509.NewCertPool()

		for _, a := range anchors {
			pem, err := os.ReadFile(a)
			if err != nil {
				return nil, fmt.Errorf("KKDCP: reading http_anchors %q: %w", a, err)
			}

			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("KKDCP: no certificate found in http_anchors %q", a)
			}
		}

		tlsConf.RootCAs = pool
	}

	dialer := cl.settings.dialer
	tr := &http.Transport{
		TLSClientConfig: tlsConf,
		DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
	}

	return &http.Client{Transport: tr, Timeout: 30 * time.Second}, nil
}

// httpAnchors is the realm's http_anchors as filesystem paths. Only MIT's
// `FILE:` form (and a bare path) is taken; `DIR:` and `ENV:` are not.
func (cl *Client) httpAnchors(realm string) []string {
	var out []string

	for _, r := range cl.Config.Realms {
		if r.Realm != realm {
			continue
		}

		for _, a := range r.Values["http_anchors"] {
			out = append(out, strings.TrimPrefix(a, "FILE:"))
		}
	}

	return out
}

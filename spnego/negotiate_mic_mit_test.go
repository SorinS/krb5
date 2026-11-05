package spnego_test

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/gsskrb5"
	"github.com/go-krb5/krb5/service"
	"github.com/go-krb5/krb5/spnego"
)

// recvTokErr is recvTok that reports an error instead of failing the test, for
// the leg where a rejected MIC makes the peer hang up.
func recvTokErr(r io.Reader) (byte, []byte, error) {
	h := make([]byte, 5)
	if _, err := io.ReadFull(r, h); err != nil {
		return 0, nil, err
	}

	tok := make([]byte, binary.BigEndian.Uint32(h[1:]))
	if _, err := io.ReadFull(r, tok); err != nil {
		return 0, nil, err
	}

	return h[0], tok, nil
}

// krbMechListDER is the MechTypeList DER (the mechListMIC payload) for a lone
// Kerberos offer, as the acceptor computes it.
func krbMechListDER(t *testing.T) []byte {
	t.Helper()

	der, err := asn1.Marshal([]asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()},
		asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	require.NoError(t, err)

	return der
}

// MIT's gss-client -spnego against an acceptor that sends a mechListMIC: MIT
// verifies ours (it would fail the context otherwise) and sends its own in a
// third leg, which we verify. A corrupted MIC makes MIT reject the context.
// This oracles the mechListMIC payload and key usage both ways; the acceptor
// uses the same gsskrb5 MIC calls that spnego.Accept/Continue wire up.
func TestMITClient_Acceptor_MechListMIC(t *testing.T) {
	m := newMITSPNEGO(t)
	env := m.kinitAlice(t)

	der := krbMechListDER(t)

	for _, tc := range []struct {
		name    string
		corrupt bool
	}{
		{"valid MIC", false},
		{"corrupted MIC", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)

			defer l.Close()

			port := l.Addr().(*net.TCPAddr).Port
			cmd := exec.Command(filepath.Join(m.bin, "gss-client"), "-port", fmt.Sprint(port), "-spnego",
				"127.0.0.1", "host@svc.a.test", "hello goose")
			cmd.Env = env

			done := make(chan []byte, 1)
			go func() { o, _ := cmd.CombinedOutput(); done <- o }()

			c, err := l.Accept()
			require.NoError(t, err)

			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(20 * time.Second))

			recvTok(t, c) // noop|contextNext
			_, initTok := recvTok(t, c)

			var st spnego.SPNEGOToken
			require.NoError(t, st.Unmarshal(initTok))

			gctx, apRep, err := gsskrb5.Accept(st.NegTokenInit.MechTokenBytes,
				service.NewSettings(m.kt, service.DecodePAC(false)), gsskrb5.AcceptOptions{})
			require.NoError(t, err)

			mic, err := gctx.GetMIC(der)
			require.NoError(t, err)

			if tc.corrupt {
				mic[len(mic)-1] ^= 0xff
			}

			resp, err := (&spnego.SPNEGOToken{Resp: true, NegTokenResp: spnego.NegTokenResp{
				NegState:      asn1.Enumerated(spnego.NegStateAcceptCompleted),
				SupportedMech: gssapi.OIDKRB5.OID(),
				ResponseToken: apRep,
				MechListMIC:   mic,
			}}).Marshal()
			require.NoError(t, err)

			sendTok(t, c, tokContext, resp)

			if tc.corrupt {
				// MIT rejects our MIC: it does not complete the context, and
				// never prints the signature line.
				o := <-done
				assert.NotContains(t, string(o), "Signature verified.", string(o))
				return
			}

			// Leg 3: MIT returns its own mechListMIC, which we verify.
			f, leg3, err := recvTokErr(c)
			require.NoError(t, err, "MIT should send its mechListMIC")
			require.Equal(t, byte(tokContext), f)

			var st3 spnego.SPNEGOToken
			require.NoError(t, st3.Unmarshal(leg3))
			require.NotEmpty(t, st3.NegTokenResp.MechListMIC, "MIT's reciprocal mechListMIC")
			require.NoError(t, gctx.VerifyMIC(der, st3.NegTokenResp.MechListMIC))

			// Data phase, so gss-client reaches "Signature verified.".
			for {
				fl, dtok, derr := recvTokErr(c)
				if derr != nil || fl&tokNoop != 0 {
					break
				}

				msg := dtok
				if fl&tokWrapped != 0 {
					msg, _, err = gctx.Unwrap(dtok)
					require.NoError(t, err)
				}

				if fl&tokSendMIC != 0 {
					dmic, err := gctx.GetMIC(msg)
					require.NoError(t, err)
					sendTok(t, c, tokMIC, dmic)
				} else {
					sendTok(t, c, tokNoop, nil)
				}
			}

			o := <-done
			assert.Contains(t, string(o), "Signature verified.", string(o))
		})
	}
}

// When the initiator offers more than Kerberos and includes a mechListMIC,
// our acceptor verifies it and sends its own back (RFC 4178 section 5). A
// valid MIC is accepted and a tampered one rejected. MIT's single-mechanism
// client does not take this path, so it is driven with our own initiator over
// a two-mechanism list (Kerberos first, then NTLM, which we do not implement
// but may be offered).
func TestAccept_InitiatorMechListMIC(t *testing.T) {
	m := newMITSPNEGO(t)

	cl := client.NewWithPassword("alice", "A.TEST", "alice-pw", m.cfg)
	require.NoError(t, cl.Login())

	// A non-mutual initiator context is established at once, so it can sign
	// the mech list now.
	gctx, krbTok, err := gsskrb5.NewInitiator(cl, "host/svc.a.test", gsskrb5.InitOptions{})
	require.NoError(t, err)

	mechs := []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID(), {1, 3, 6, 1, 4, 1, 311, 2, 2, 10}}

	der, err := asn1.Marshal(mechs, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	require.NoError(t, err)

	mic, err := gctx.GetMIC(der)
	require.NoError(t, err)

	build := func(mic []byte) []byte {
		b, err := (&spnego.SPNEGOToken{Init: true, NegTokenInit: spnego.NegTokenInit{
			MechTypes: mechs, MechTokenBytes: krbTok, MechListMIC: mic,
		}}).Marshal()
		require.NoError(t, err)

		return b
	}

	s := service.NewSettings(m.kt, service.DecodePAC(false))

	// Valid: accepted, and the acceptor's reply carries a mechListMIC the
	// initiator verifies.
	ac, out, err := spnego.Accept(build(mic), s, spnego.AcceptOptions{})
	require.NoError(t, err)
	require.True(t, ac.Established())
	assert.True(t, ac.MechListMICExchanged())

	var resp spnego.SPNEGOToken
	require.NoError(t, resp.Unmarshal(out))
	require.NotEmpty(t, resp.NegTokenResp.MechListMIC)
	require.NoError(t, gctx.VerifyMIC(der, resp.NegTokenResp.MechListMIC))

	// Tampered: the AP-REQ is replayed, so a fresh ticket avoids the replay
	// cache; the mechListMIC is wrong and the acceptor rejects it.
	gctx2, krbTok2, err := gsskrb5.NewInitiator(cl, "host/svc.a.test", gsskrb5.InitOptions{})
	require.NoError(t, err)

	mic2, err := gctx2.GetMIC(der)
	require.NoError(t, err)
	mic2[len(mic2)-1] ^= 0xff

	bad, err := (&spnego.SPNEGOToken{Init: true, NegTokenInit: spnego.NegTokenInit{
		MechTypes: mechs, MechTokenBytes: krbTok2, MechListMIC: mic2,
	}}).Marshal()
	require.NoError(t, err)

	_, _, err = spnego.Accept(bad, s, spnego.AcceptOptions{})
	require.Error(t, err, "a tampered mechListMIC must be rejected")
	assert.Contains(t, err.Error(), "mechListMIC")
}

// Continue's mechListMIC branch end to end, ours to ours: the acceptor sends a
// mechListMIC, the initiator verifies it and reciprocates with its own, which
// the acceptor then verifies. (MIT's gss-server sends no MIC for a lone
// mechanism, so this is the only end-to-end exercise of the initiator's branch;
// the MIC calls themselves are the gsskrb5 ones checked against MIT elsewhere.)
func TestContinue_MechListMIC(t *testing.T) {
	m := newMITSPNEGO(t)

	cl := client.NewWithPassword("alice", "A.TEST", "alice-pw", m.cfg)
	require.NoError(t, cl.Login())

	ic, tok, err := spnego.NewInitiator(cl, "host/svc.a.test", spnego.InitOptions{Flags: gsskrb5.FlagMutual})
	require.NoError(t, err)

	// Acceptor side: process the AP-REQ, then hand-build an accept-completed
	// reply that carries a mechListMIC (over the lone-Kerberos mech list, which
	// matches the initiator's), as a MIC-sending acceptor would.
	var st spnego.SPNEGOToken
	require.NoError(t, st.Unmarshal(tok))

	gctx, apRep, err := gsskrb5.Accept(st.NegTokenInit.MechTokenBytes,
		service.NewSettings(m.kt, service.DecodePAC(false)), gsskrb5.AcceptOptions{})
	require.NoError(t, err)

	der := krbMechListDER(t)

	accMIC, err := gctx.GetMIC(der)
	require.NoError(t, err)

	reply, err := (&spnego.SPNEGOToken{Resp: true, NegTokenResp: spnego.NegTokenResp{
		NegState:      asn1.Enumerated(spnego.NegStateAcceptCompleted),
		SupportedMech: gssapi.OIDKRB5.OID(),
		ResponseToken: apRep,
		MechListMIC:   accMIC,
	}}).Marshal()
	require.NoError(t, err)

	// Initiator verifies the acceptor's MIC and returns its own.
	back, err := ic.Continue(reply)
	require.NoError(t, err)
	require.True(t, ic.Established())
	assert.True(t, ic.MechListMICExchanged())
	require.NotNil(t, back, "the initiator reciprocates with its mechListMIC")

	var st2 spnego.SPNEGOToken
	require.NoError(t, st2.Unmarshal(back))
	require.NotEmpty(t, st2.NegTokenResp.MechListMIC)
	require.NoError(t, gctx.VerifyMIC(der, st2.NegTokenResp.MechListMIC), "acceptor verifies the initiator's MIC")
}

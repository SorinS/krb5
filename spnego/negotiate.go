package spnego

import (
	"errors"
	"fmt"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/SorinS/krb5/client"
	"github.com/SorinS/krb5/gssapi"
	"github.com/SorinS/krb5/gsskrb5"
	"github.com/SorinS/krb5/service"
)

// This file is the programmatic, multi-leg SPNEGO (RFC 4178) built on a
// Kerberos GSS context (gsskrb5): an initiator and an acceptor that exchange
// NegTokenInit/NegTokenResp, carry the AP-REP for mutual authentication, and
// exchange a mechListMIC when the negotiation needs one. It is distinct from
// the stateless HTTP handler (SPNEGOKRB5Authenticate), which answers a single
// browser leg and does neither mutual authentication nor a mechListMIC.

// InitOptions are an initiator's choices (as gsskrb5: FlagMutual, delegation,
// channel bindings).
type InitOptions = gsskrb5.InitOptions

// AcceptOptions are an acceptor's choices (as gsskrb5: channel bindings).
type AcceptOptions = gsskrb5.AcceptOptions

// Context is a SPNEGO security context, established or in progress, wrapping
// the negotiated Kerberos GSS context. Once Established, the embedded GSS
// context (GSS) does per-message Wrap/Unwrap/GetMIC and carries the peer's
// identity and any delegated credentials.
type Context struct {
	g           *gsskrb5.Context
	settings    *service.Settings
	mechListDER []byte // the MechTypeList DER, the mechListMIC payload
	initiator   bool
	micSent     bool
	micVerified bool
	established bool
}

// Established reports whether the negotiation is complete.
func (c *Context) Established() bool { return c.established }

// GSS returns the underlying Kerberos GSS context, for per-message tokens and
// the peer's credentials. It is nil until the context is established.
func (c *Context) GSS() *gsskrb5.Context { return c.g }

// MechListMICExchanged reports whether a mechListMIC was sent and the peer's
// was verified (RFC 4178 downgrade protection took place).
func (c *Context) MechListMICExchanged() bool { return c.micSent && c.micVerified }

// mechListDER encodes a MechTypeList (SEQUENCE OF MechType): the payload a
// mechListMIC is computed over.
func mechListDER(mechs []asn1.ObjectIdentifier) ([]byte, error) {
	return asn1.Marshal(mechs, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
}

func initToken(n NegTokenInit) ([]byte, error) {
	return (&SPNEGOToken{Init: true, NegTokenInit: n}).Marshal()
}

func respToken(n NegTokenResp) ([]byte, error) {
	return (&SPNEGOToken{Resp: true, NegTokenResp: n}).Marshal()
}

// NewInitiator starts a SPNEGO context to the service spn, offering Kerberos
// with an optimistic AP-REQ. It returns the context and the first token (a
// NegTokenInit) for the acceptor; the acceptor's NegTokenResp goes to
// Continue. With FlagMutual the context is established once Continue has
// checked the AP-REP; without it, once Continue has seen accept-completed.
func NewInitiator(cl *client.Client, spn string, opts InitOptions) (*Context, []byte, error) {
	g, krbTok, err := gsskrb5.NewInitiator(cl, spn, opts)
	if err != nil {
		return nil, nil, err
	}

	mechs := []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()}

	der, err := mechListDER(mechs)
	if err != nil {
		return nil, nil, err
	}

	tok, err := initToken(NegTokenInit{MechTypes: mechs, MechTokenBytes: krbTok})
	if err != nil {
		return nil, nil, err
	}

	return &Context{g: g, mechListDER: der, initiator: true}, tok, nil
}

// Continue takes the acceptor's NegTokenResp and advances the context. It
// returns a token to send back when the negotiation needs another leg (the
// initiator's mechListMIC), or nil when nothing more is owed; Established then
// reports the outcome.
func (c *Context) Continue(token []byte) ([]byte, error) {
	var st SPNEGOToken
	if err := st.Unmarshal(token); err != nil {
		return nil, fmt.Errorf("spnego: parsing acceptor token: %w", err)
	}

	if !st.Resp {
		return nil, errors.New("spnego: expected a NegTokenResp from the acceptor")
	}

	r := st.NegTokenResp

	state := NegState(r.NegState)

	switch state {
	case NegStateReject:
		return nil, errors.New("spnego: acceptor rejected the negotiation")
	case NegStateRequestMIC, NegStateAcceptIncomplete, NegStateAcceptCompleted:
	default:
		return nil, fmt.Errorf("spnego: unexpected negotiation state %d", r.NegState)
	}

	// The acceptor must not answer with a mechanism we did not offer.
	if len(r.SupportedMech) > 0 &&
		!r.SupportedMech.Equal(gssapi.OIDKRB5.OID()) && !r.SupportedMech.Equal(gssapi.OIDMSLegacyKRB5.OID()) {
		return nil, fmt.Errorf("spnego: acceptor selected a non-Kerberos mechanism %s", r.SupportedMech)
	}

	// The AP-REP (mutual authentication), if the acceptor sent one.
	if len(r.ResponseToken) > 0 {
		if err := c.g.Continue(r.ResponseToken); err != nil {
			return nil, fmt.Errorf("spnego: acceptor response token: %w", err)
		}
	}

	var out []byte

	// The acceptor's mechListMIC: verify it, and reciprocate with ours (RFC
	// 4178 section 5), which the acceptor then verifies.
	if len(r.MechListMIC) > 0 {
		if err := c.g.VerifyMIC(c.mechListDER, r.MechListMIC); err != nil {
			return nil, fmt.Errorf("spnego: acceptor mechListMIC: %w", err)
		}

		c.micVerified = true

		mic, err := c.g.GetMIC(c.mechListDER)
		if err != nil {
			return nil, fmt.Errorf("spnego: generating mechListMIC: %w", err)
		}

		c.micSent = true

		out, err = respToken(NegTokenResp{NegState: asn1.Enumerated(NegStateAcceptCompleted), MechListMIC: mic})
		if err != nil {
			return nil, err
		}
	}

	// Only accept-completed establishes the context: accept-incomplete and
	// request-mic mean the acceptor is not done, even when a valid AP-REP has
	// already established the underlying GSS context (which, for a non-mutual
	// initiator, is established from the start).
	c.established = state == NegStateAcceptCompleted && c.g.Established()

	return out, nil
}

// Accept checks an initiator's SPNEGO token with the service settings (its
// keytab, replay cache, clock skew), and returns the context and the token to
// send back (a NegTokenResp). When the token is the start of a negotiation
// with Kerberos offered first, it carries the AP-REQ and the reply carries the
// AP-REP for mutual authentication; a mechListMIC is exchanged when the
// initiator sent one or offered more than Kerberos. When Kerberos is not first
// (or carries no optimistic token), the returned context has no GSS context
// yet (GSS is nil and Established is false): the reply is accept-incomplete,
// and completing the negotiation with such an initiator is not yet supported.
func Accept(token []byte, s *service.Settings, opts AcceptOptions) (*Context, []byte, error) {
	var st SPNEGOToken

	st.settings = s
	if err := st.Unmarshal(token); err != nil {
		return nil, nil, fmt.Errorf("spnego: parsing initiator token: %w", err)
	}

	if !st.Init {
		return nil, nil, errors.New("spnego: expected a NegTokenInit from the initiator")
	}

	n := st.NegTokenInit

	if len(n.MechTypes) == 0 {
		return reject("spnego: no mechanism offered")
	}

	offered, first := mechTypePreferred(n.MechTypes)
	if !offered {
		return reject("spnego: no Kerberos mechanism offered")
	}

	der, err := mechListDER(n.MechTypes)
	if err != nil {
		return nil, nil, err
	}

	// Kerberos not first (Windows lists NEGOEX or NTLM first): answer
	// accept-incomplete so the initiator continues with Kerberos. A
	// mechListMIC is then required (RFC 4178 section 5); it is exchanged once
	// the context exists. The continuation (the AP-REQ in a NegTokenResp) is
	// not yet handled, so this half completes only with an initiator that
	// retries Kerberos in a fresh NegTokenInit.
	if !first || len(n.MechTokenBytes) == 0 {
		out, err := respToken(NegTokenResp{
			NegState:      asn1.Enumerated(NegStateAcceptIncomplete),
			SupportedMech: gssapi.OIDKRB5.OID(),
		})

		return &Context{settings: s, mechListDER: der}, out, err
	}

	g, apRep, err := gsskrb5.Accept(n.MechTokenBytes, s, opts)
	if err != nil {
		return reject(fmt.Sprintf("spnego: %v", err))
	}

	resp := NegTokenResp{
		NegState:      asn1.Enumerated(NegStateAcceptCompleted),
		SupportedMech: gssapi.OIDKRB5.OID(),
		ResponseToken: apRep,
	}

	c := &Context{g: g, settings: s, mechListDER: der, established: g.Established()}

	// A mechListMIC is verified when present, and sent back when the
	// initiator sent one or offered more than one mechanism (so the mech list
	// is worth protecting). For a lone optimistic Kerberos, none is used, as
	// MIT does not.
	if len(n.MechListMIC) > 0 {
		if err := g.VerifyMIC(der, n.MechListMIC); err != nil {
			return reject(fmt.Sprintf("spnego: initiator mechListMIC: %v", err))
		}

		c.micVerified = true
	}

	if len(n.MechListMIC) > 0 || len(n.MechTypes) > 1 {
		mic, err := g.GetMIC(der)
		if err != nil {
			return nil, nil, fmt.Errorf("spnego: generating mechListMIC: %w", err)
		}

		resp.MechListMIC = mic
		c.micSent = true
	}

	out, err := respToken(resp)

	return c, out, err
}

// reject builds a NegTokenResp with the reject state and the given error.
func reject(msg string) (*Context, []byte, error) {
	out, err := respToken(NegTokenResp{NegState: asn1.Enumerated(NegStateReject)})
	if err != nil {
		return nil, nil, err
	}

	return nil, out, errors.New(msg)
}

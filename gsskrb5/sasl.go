package gsskrb5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/SorinS/krb5/client"
)

// SASL GSSAPI security layers (RFC 4752 3.3).
const (
	LayerNone            = 1
	LayerIntegrity       = 2
	LayerConfidentiality = 4
)

// maxBuffer is the largest wrapped message we take, as we tell the server.
const maxBuffer = 0xffffff

// SASL is the client side of SASL's GSSAPI mechanism (RFC 4752) over a
// Kerberos context: the context's tokens, then the server's offer of
// security layers and our choice. With the integrity or confidentiality
// layer, every message after the exchange goes through Wrap and Unwrap
// (WrapMessage, UnwrapMessage frame them as RFC 4752 3.3 has it).
//
// Its methods InitSecContext, InitSecContextWithOptions, NegotiateSaslAuth
// and DeleteSecContext are those of go-ldap's GSSAPIClient interface, so a
// *SASL can bind with go-ldap's GSSAPIBind too: go-ldap does not wrap
// messages after the bind, so Layers should then be LayerNone (the
// default).
type SASL struct {
	Client *client.Client
	// Layers is a mask of the layers we take (Layer*), the strongest the
	// server offers chosen; LayerNone when zero.
	Layers byte
	// AuthzID is the authorization identity sent with the choice, or "".
	AuthzID string

	ctx     *Context
	layer   byte
	maxSend uint32
}

// NewSASL returns a SASL GSSAPI client for the Kerberos client cl, taking
// the layers in the mask (Layer*).
func NewSASL(cl *client.Client, layers byte) *SASL {
	return &SASL{Client: cl, Layers: layers}
}

// Layer returns the layer in force once NegotiateSaslAuth has chosen it.
func (s *SASL) Layer() byte { return s.layer }

// MaxSend returns the largest wrapped message the server takes.
func (s *SASL) MaxSend() uint32 { return s.maxSend }

// spnOf turns a GSS host-based name ("ldap@dc.example.com") into a
// service principal ("ldap/dc.example.com"); a principal stays as it is.
func spnOf(target string) string {
	if strings.Contains(target, "/") {
		return target
	}

	return strings.Replace(target, "@", "/", 1)
}

// InitSecContext is go-ldap's GSSAPIClient's: with token nil it returns
// the first context token for target ("ldap@host" or "ldap/host"), and
// then takes the server's (the AP-REP).
func (s *SASL) InitSecContext(target string, token []byte) ([]byte, bool, error) {
	return s.InitSecContextWithOptions(target, token, nil)
}

// InitSecContextWithOptions is InitSecContext; the options (go-ldap's
// context flags) are added to mutual authentication, integrity and
// confidentiality, which RFC 4752 asks for.
func (s *SASL) InitSecContextWithOptions(target string, token []byte, options []int) ([]byte, bool, error) {
	if token == nil {
		var f uint32 = FlagMutual | FlagInteg | FlagConf

		for _, o := range options {
			f |= uint32(o) &^ FlagDeleg
		}

		ctx, out, err := NewInitiator(s.Client, spnOf(target), InitOptions{Flags: f})
		if err != nil {
			return nil, false, err
		}

		s.ctx = ctx

		return out, true, nil
	}

	if s.ctx == nil {
		return nil, false, ErrContext
	}

	if err := s.ctx.Continue(token); err != nil {
		return nil, false, err
	}

	return nil, false, nil
}

// NegotiateSaslAuth is go-ldap's GSSAPIClient's: it reads the server's
// offer (a Wrap token: the layers it supports and its largest message),
// chooses the strongest layer we take, and returns our choice in a Wrap
// token, with the authorization identity.
func (s *SASL) NegotiateSaslAuth(token []byte, authzid string) ([]byte, error) {
	if s.ctx == nil || !s.ctx.Established() {
		return nil, ErrContext
	}

	offer, _, err := s.ctx.Unwrap(token)
	if err != nil {
		return nil, fmt.Errorf("gsskrb5: the server's SASL offer: %w", err)
	}

	if len(offer) != 4 {
		return nil, errors.New("gsskrb5: the server's SASL offer is not 4 bytes")
	}

	want := s.Layers
	if want == 0 {
		want = LayerNone
	}

	var layer byte

	for _, l := range []byte{LayerConfidentiality, LayerIntegrity, LayerNone} {
		if want&l != 0 && offer[0]&l != 0 {
			layer = l
			break
		}
	}

	if layer == 0 {
		return nil, fmt.Errorf("gsskrb5: the server offers SASL layers %#x, we take %#x", offer[0], want)
	}

	s.maxSend = uint32(offer[1])<<16 | uint32(offer[2])<<8 | uint32(offer[3])
	if layer != LayerNone && s.maxSend == 0 {
		return nil, errors.New("gsskrb5: the server offers a layer with no room for messages")
	}

	if authzid == "" {
		authzid = s.AuthzID
	}

	var max uint32
	if layer != LayerNone {
		max = maxBuffer
	}

	choice := []byte{layer, byte(max >> 16), byte(max >> 8), byte(max)}
	choice = append(choice, authzid...)

	out, err := s.ctx.Wrap(choice, false)
	if err != nil {
		return nil, err
	}

	s.layer = layer

	return out, nil
}

// DeleteSecContext is go-ldap's GSSAPIClient's: it drops the context.
func (s *SASL) DeleteSecContext() error {
	s.ctx = nil
	s.layer = 0

	return nil
}

// WrapMessage protects a message under the layer chosen: a 4-byte
// big-endian length and a Wrap token (sealed for confidentiality), RFC
// 4752 3.3; with LayerNone, the message as it is.
func (s *SASL) WrapMessage(msg []byte) ([]byte, error) {
	if s.layer == LayerNone || s.layer == 0 {
		return msg, nil
	}

	w, err := s.ctx.Wrap(msg, s.layer == LayerConfidentiality)
	if err != nil {
		return nil, err
	}

	if s.maxSend != 0 && uint32(len(w)) > s.maxSend {
		return nil, fmt.Errorf("gsskrb5: a wrapped message of %d bytes, more than the server's %d", len(w), s.maxSend)
	}

	out := make([]byte, 4, 4+len(w))
	binary.BigEndian.PutUint32(out, uint32(len(w)))

	return append(out, w...), nil
}

// UnwrapMessage reads a Wrap token (without its length) under the layer
// chosen.
func (s *SASL) UnwrapMessage(token []byte) ([]byte, error) {
	msg, sealed, err := s.ctx.Unwrap(token)
	if err != nil {
		return nil, err
	}

	if s.layer == LayerConfidentiality && !sealed {
		return nil, errors.New("gsskrb5: a message without confidentiality under the confidentiality layer")
	}

	return msg, nil
}

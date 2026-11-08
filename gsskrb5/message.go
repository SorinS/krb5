package gsskrb5

import (
	"crypto/hmac"
	"encoding/binary"

	"github.com/SorinS/krb5/crypto"
	"github.com/SorinS/krb5/iana/keyusage"
)

// Wrap and MIC token flags (RFC 4121 4.2.2).
const (
	tfSentByAcceptor = 1
	tfSealed         = 2
	tfAcceptorSubkey = 4
)

func (c *Context) tokenFlags(sealed bool) byte {
	var f byte
	if !c.initiator {
		f |= tfSentByAcceptor
	}

	if sealed {
		f |= tfSealed
	}

	if c.acceptorSubkey {
		f |= tfAcceptorSubkey
	}

	return f
}

func signUsage(senderInitiator bool) uint32 {
	if senderInitiator {
		return keyusage.GSSAPI_INITIATOR_SIGN
	}

	return keyusage.GSSAPI_ACCEPTOR_SIGN
}

func sealUsage(senderInitiator bool) uint32 {
	if senderInitiator {
		return keyusage.GSSAPI_INITIATOR_SEAL
	}

	return keyusage.GSSAPI_ACCEPTOR_SEAL
}

// checkTokenFlags: a received token is the peer's, and names the acceptor
// subkey exactly when the context uses one.
func (c *Context) checkTokenFlags(f byte, sealedOK bool) bool {
	if (f&tfSentByAcceptor != 0) != c.initiator {
		return false
	}

	if (f&tfAcceptorSubkey != 0) != c.acceptorSubkey {
		return false
	}

	if !sealedOK && f&tfSealed != 0 {
		return false
	}

	return f&0xf8 == 0
}

// checkSeq checks a received token's sequence number: the next one, or
// (without FlagSequence) a later one; with FlagReplay or FlagSequence an
// earlier one, a replay, is refused.
func (c *Context) checkSeq(seq uint64) error {
	switch {
	case seq == c.recvSeq:
		c.recvSeq++
	case seq < c.recvSeq:
		if c.flags&(FlagReplay|FlagSequence) != 0 {
			return ErrSequence
		}
	default:
		if c.flags&FlagSequence != 0 {
			return ErrSequence
		}

		c.recvSeq = seq + 1
	}

	return nil
}

// GetMIC returns a MIC token for the message (RFC 4121 4.2.6.1).
func (c *Context) GetMIC(msg []byte) ([]byte, error) {
	if !c.established {
		return nil, ErrContext
	}

	h := []byte{0x04, 0x04, c.tokenFlags(false), 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint64(h[8:], c.sendSeq)

	et, err := crypto.GetEtype(c.key.KeyType)
	if err != nil {
		return nil, err
	}

	ck, err := et.GetChecksumHash(c.key.KeyValue, append(append([]byte(nil), msg...), h...), signUsage(c.initiator))
	if err != nil {
		return nil, err
	}

	c.sendSeq++

	return append(h, ck...), nil
}

// VerifyMIC checks a MIC token over the message.
func (c *Context) VerifyMIC(msg, token []byte) error {
	if !c.established {
		return ErrContext
	}

	if len(token) < 16 || token[0] != 0x04 || token[1] != 0x04 || !c.checkTokenFlags(token[2], false) {
		return ErrToken
	}

	for _, b := range token[3:8] {
		if b != 0xff {
			return ErrToken
		}
	}

	et, err := crypto.GetEtype(c.key.KeyType)
	if err != nil {
		return err
	}

	data := append(append([]byte(nil), msg...), token[:16]...)
	if !et.VerifyChecksum(c.key.KeyValue, data, token[16:], signUsage(!c.initiator)) {
		return ErrToken
	}

	return c.checkSeq(binary.BigEndian.Uint64(token[8:]))
}

// Wrap returns a Wrap token for the message (RFC 4121 4.2.6.2): encrypted
// when conf, else with a checksum. Its RRC is 0 (as MIT sends); Unwrap
// reads any.
func (c *Context) Wrap(msg []byte, conf bool) ([]byte, error) {
	if !c.established {
		return nil, ErrContext
	}

	et, err := crypto.GetEtype(c.key.KeyType)
	if err != nil {
		return nil, err
	}

	h := []byte{0x05, 0x04, c.tokenFlags(conf), 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint64(h[8:], c.sendSeq)

	var out []byte

	if conf {
		// EC 0: the profiles here need no filler. The header, encrypted
		// after the message, says so.
		p := append(append([]byte(nil), msg...), h...)

		_, ct, err := et.EncryptMessage(c.key.KeyValue, p, sealUsage(c.initiator))
		if err != nil {
			return nil, err
		}

		out = append(h, ct...)
	} else {
		data := append(append([]byte(nil), msg...), h...)

		ck, err := et.GetChecksumHash(c.key.KeyValue, data, sealUsage(c.initiator))
		if err != nil {
			return nil, err
		}

		binary.BigEndian.PutUint16(h[4:], uint16(len(ck)))
		out = append(append(h, msg...), ck...)
	}

	c.sendSeq++

	return out, nil
}

// Unwrap returns the message of a Wrap token, and whether it came
// encrypted.
func (c *Context) Unwrap(token []byte) ([]byte, bool, error) {
	if !c.established {
		return nil, false, ErrContext
	}

	if len(token) < 16 || token[0] != 0x05 || token[1] != 0x04 || token[3] != 0xff || !c.checkTokenFlags(token[2], true) {
		return nil, false, ErrToken
	}

	et, err := crypto.GetEtype(c.key.KeyType)
	if err != nil {
		return nil, false, err
	}

	ec := int(binary.BigEndian.Uint16(token[4:]))
	rrc := int(binary.BigEndian.Uint16(token[6:]))
	seq := binary.BigEndian.Uint64(token[8:])

	// Undo the right rotation of what follows the header.
	body := token[16:]
	b := make([]byte, 0, len(body))

	if len(body) > 0 {
		r := rrc % len(body)
		b = append(append(b, body[r:]...), body[:r]...)
	}

	sealed := token[2]&tfSealed != 0

	var msg []byte

	if sealed {
		p, err := et.DecryptMessage(c.key.KeyValue, b, sealUsage(!c.initiator))
		if err != nil {
			return nil, true, err
		}

		if len(p) < 16+ec {
			return nil, true, ErrToken
		}

		// The header inside: the token's, but with RRC 0.
		inner := p[len(p)-16:]
		for i := 0; i < 16; i++ {
			want := token[i]
			if i == 6 || i == 7 {
				want = 0
			}

			if inner[i] != want {
				return nil, true, ErrToken
			}
		}

		msg = p[:len(p)-16-ec]
	} else {
		if len(b) < ec {
			return nil, false, ErrToken
		}

		msg = b[:len(b)-ec]

		// The checksum is over the message and the header with EC and RRC 0.
		h := append([]byte(nil), token[:16]...)
		clear(h[4:8])
		data := append(append([]byte(nil), msg...), h...)

		want, err := et.GetChecksumHash(c.key.KeyValue, data, sealUsage(!c.initiator))
		if err != nil {
			return nil, false, err
		}

		if !hmac.Equal(want, b[len(b)-ec:]) {
			return nil, false, ErrToken
		}
	}

	if err := c.checkSeq(seq); err != nil {
		return nil, sealed, err
	}

	return append([]byte(nil), msg...), sealed, nil
}

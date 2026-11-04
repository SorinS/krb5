package spake

import (
	"errors"
	"fmt"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/types"
)

// PA-SPAKE ::= CHOICE { support [0], challenge [1], response [2],
// encdata [3] }.
const (
	ChoiceSupport   = 0
	ChoiceChallenge = 1
	ChoiceResponse  = 2
	ChoiceEncData   = 3
)

// SecondFactor is SPAKESecondFactor.
type SecondFactor struct {
	Type int32  `asn1:"explicit,tag:0"`
	Data []byte `asn1:"explicit,optional,tag:1"`
}

type support struct {
	Groups []int32 `asn1:"explicit,tag:0"`
}

type challenge struct {
	Group   int32          `asn1:"explicit,tag:0"`
	PubKey  []byte         `asn1:"explicit,tag:1"`
	Factors []SecondFactor `asn1:"explicit,tag:2"`
}

type response struct {
	PubKey []byte              `asn1:"explicit,tag:0"`
	Factor types.EncryptedData `asn1:"explicit,tag:1"`
}

// Message is a PA-SPAKE: Choice says which of its fields are set.
type Message struct {
	Choice  int
	Groups  []int32             // support
	Group   int32               // challenge
	PubKey  []byte              // challenge, response
	Factors []SecondFactor      // challenge
	Enc     types.EncryptedData // response's factor, encdata
}

var errMalformed = errors.New("spake: malformed PA-SPAKE")

func choice(n int, v any) ([]byte, error) {
	b, err := asn1.Marshal(v)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: n, IsCompound: true, Bytes: b})
}

// Marshal is the message's DER.
func (m *Message) Marshal() ([]byte, error) {
	switch m.Choice {
	case ChoiceSupport:
		return choice(m.Choice, support{Groups: m.Groups})
	case ChoiceChallenge:
		return choice(m.Choice, challenge{Group: m.Group, PubKey: m.PubKey, Factors: m.Factors})
	case ChoiceResponse:
		return choice(m.Choice, response{PubKey: m.PubKey, Factor: m.Enc})
	case ChoiceEncData:
		return choice(m.Choice, m.Enc)
	}

	return nil, fmt.Errorf("spake: no choice %d", m.Choice)
}

// Unmarshal reads a PA-SPAKE.
func (m *Message) Unmarshal(b []byte) error {
	var rv asn1.RawValue

	rest, err := asn1.Unmarshal(b, &rv)
	if err != nil || len(rest) > 0 || rv.Class != asn1.ClassContextSpecific || !rv.IsCompound || rv.Tag > ChoiceEncData {
		return errMalformed
	}

	*m = Message{Choice: rv.Tag}

	var target any

	var (
		s support
		c challenge
		r response
	)

	switch rv.Tag {
	case ChoiceSupport:
		target = &s
	case ChoiceChallenge:
		target = &c
	case ChoiceResponse:
		target = &r
	case ChoiceEncData:
		target = &m.Enc
	}

	if rest, err := asn1.Unmarshal(rv.Bytes, target); err != nil || len(rest) > 0 {
		return errMalformed
	}

	switch rv.Tag {
	case ChoiceSupport:
		if len(s.Groups) == 0 {
			return errMalformed
		}

		m.Groups = s.Groups
	case ChoiceChallenge:
		if len(c.Factors) == 0 {
			return errMalformed
		}

		m.Group, m.PubKey, m.Factors = c.Group, c.PubKey, c.Factors
	case ChoiceResponse:
		m.PubKey, m.Enc = r.PubKey, r.Factor
	}

	return nil
}

// Client is the client's side of one SPAKE exchange.
type Client struct {
	// Groups are the groups the client takes, in its order of preference.
	Groups []int32

	support []byte // the support message sent, for the transcript

	group  *Group
	ikey   types.EncryptionKey
	wbytes []byte
	k      []byte
	thash  []byte
	pubkey []byte
}

// NewClient is a client taking these groups (MIT's spake_preauth_groups;
// edwards25519 alone when there are none).
func NewClient(groups []int32) *Client {
	if len(groups) == 0 {
		groups = []int32{Edwards25519}
	}

	return &Client{Groups: groups}
}

// Takes is whether the client takes the group.
func (c *Client) Takes(id int32) bool {
	for _, g := range c.Groups {
		if g == id {
			_, ok := GroupByID(id)
			return ok
		}
	}

	return false
}

// Support is the support message (PA-SPAKE's value), kept for the
// transcript.
func (c *Client) Support() ([]byte, error) {
	m := Message{Choice: ChoiceSupport, Groups: c.Groups}

	b, err := m.Marshal()
	if err != nil {
		return nil, err
	}

	c.support = b

	return b, nil
}

// Challenge answers the KDC's challenge (its DER, as received) with the
// initial reply key (the client's long-term key) and a private scalar
// (nil: a new one): the transcript, w, the public key and K. The group must
// be one the client takes and SF-NONE offered.
func (c *Client) Challenge(der []byte, ikey types.EncryptionKey, priv []byte) error {
	var m Message
	if err := m.Unmarshal(der); err != nil {
		return err
	}

	if m.Choice != ChoiceChallenge {
		return fmt.Errorf("spake: a PA-SPAKE of choice %d where a challenge was expected", m.Choice)
	}

	if !c.Takes(m.Group) {
		return fmt.Errorf("spake: the KDC's group %d is not one we take", m.Group)
	}

	g, _ := GroupByID(m.Group)

	none := false
	for _, f := range m.Factors {
		none = none || f.Type == SFNone
	}

	if !none {
		return errors.New("spake: the KDC does not offer the second factor none")
	}

	wb, err := g.WBytes(ikey)
	if err != nil {
		return err
	}

	if priv == nil {
		if priv, err = g.Private(); err != nil {
			return err
		}
	}

	pub, err := g.Public(priv, wb, false)
	if err != nil {
		return err
	}

	k, err := g.Shared(priv, wb, m.PubKey, true)
	if err != nil {
		return err
	}

	th := g.Transcript(g.Transcript(nil, c.support, der), pub, nil)

	c.group, c.ikey, c.wbytes, c.k, c.thash, c.pubkey = g, ikey, wb, k, th, pub

	return nil
}

// Response is the response for a request whose KDC-REQ-BODY (the inner
// one, under FAST) is body: its PA-SPAKE value, and K'[0], the reply key.
func (c *Client) Response(body []byte) ([]byte, types.EncryptionKey, error) {
	if c.group == nil {
		return nil, types.EncryptionKey{}, errors.New("spake: no challenge answered")
	}

	k1, err := c.group.Key(c.ikey, c.wbytes, c.k, c.thash, body, 1)
	if err != nil {
		return nil, k1, err
	}

	k0, err := c.group.Key(c.ikey, c.wbytes, c.k, c.thash, body, 0)
	if err != nil {
		return nil, k0, err
	}

	f, err := asn1.Marshal(SecondFactor{Type: SFNone})
	if err != nil {
		return nil, k0, err
	}

	ed, err := crypto.GetEncryptedData(f, k1, keyusage.KEY_USAGE_SPAKE, 0)
	if err != nil {
		return nil, k0, err
	}

	m := Message{Choice: ChoiceResponse, PubKey: c.pubkey, Enc: ed}

	b, err := m.Marshal()

	return b, k0, err
}

// Answered is whether the client has answered a challenge (its reply key
// is K'[0]).
func (c *Client) Answered() bool {
	return c.group != nil
}

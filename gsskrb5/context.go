// Package gsskrb5 is the Kerberos V5 GSS-API mechanism (RFC 4121, with RFC
// 2743's token framing) on its own, without SPNEGO: what SASL GSSAPI (RFC
// 4752), MIT's gss-sample programs and other GSS-API peers speak.
//
// An initiator's context comes from a client's service ticket (NewInitiator),
// with mutual authentication, channel bindings and credential delegation
// (a forwarded TGT in a KRB-CRED in the authenticator's checksum); the
// acceptor's (Accept) checks the initiator's token against a keytab as
// service.VerifyAPREQ does and answers with an AP-REP of its own subkey, as
// MIT does. Both then make and read MIC and Wrap tokens (RFC 4121 4.2),
// with confidentiality or without, and check sequence numbers.
//
// Per-message tokens use the acceptor's subkey when it sent one, else the
// initiator's subkey, else the session key. RFC 4121's tokens need an
// encryption type of RFC 3961's simplified profile or RFC 8009's (AES,
// Camellia): contexts with RC4 or DES3 keys (RFC 4757's and RFC 1964's
// tokens) are refused. DCE-style contexts are not done.
package gsskrb5

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/SorinS/krb5/client"
	"github.com/SorinS/krb5/credentials"
	"github.com/SorinS/krb5/crypto"
	"github.com/SorinS/krb5/iana/chksumtype"
	"github.com/SorinS/krb5/iana/errorcode"
	"github.com/SorinS/krb5/iana/etypeID"
	"github.com/SorinS/krb5/iana/flags"
	"github.com/SorinS/krb5/iana/msgtype"
	"github.com/SorinS/krb5/iana/nametype"
	"github.com/SorinS/krb5/messages"
	"github.com/SorinS/krb5/service"
	"github.com/SorinS/krb5/types"
)

// OID is the Kerberos V5 mechanism's (RFC 1964).
var OID = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}

// msOID is Microsoft's mistaken Kerberos OID (Windows 2000), which Windows
// still sends and sometimes frames its tokens with.
var msOID = asn1.ObjectIdentifier{1, 2, 840, 48018, 1, 2, 2}

// Token identifiers (RFC 4121 4.1, 4.2.6).
const (
	tokAPReq = 0x0100
	tokAPRep = 0x0200
	tokError = 0x0300
	tokMIC   = 0x0404
	tokWrap  = 0x0504
)

// Context flags (RFC 2743, RFC 4121 4.1.1.1).
const (
	FlagDeleg    = 1
	FlagMutual   = 2
	FlagReplay   = 4
	FlagSequence = 8
	FlagConf     = 16
	FlagInteg    = 32
)

// The authenticator checksum's type (RFC 4121 4.1.1).
const checksumGSSAPI = chksumtype.GSSAPI

var (
	// ErrToken is a token that is not what it should be.
	ErrToken = errors.New("gsskrb5: defective token")
	// ErrContext is a call the context is not in the state for.
	ErrContext = errors.New("gsskrb5: context not established, or already")
	// ErrSequence is a token out of sequence, or replayed.
	ErrSequence = errors.New("gsskrb5: token out of sequence or replayed")
	// ErrEncType is a context whose key has no RFC 4121 tokens.
	ErrEncType = errors.New("gsskrb5: the context's encryption type has no RFC 4121 tokens (RC4, DES3)")
)

// Context is a security context, the initiator's or the acceptor's.
type Context struct {
	initiator      bool
	established    bool
	flags          uint32
	sessionKey     types.EncryptionKey
	key            types.EncryptionKey // what per-message tokens use
	acceptorSubkey bool
	sendSeq        uint64
	recvSeq        uint64
	ctime          time.Time // the initiator's authenticator time, for the AP-REP
	cusec          int

	// The acceptor's: the client and what it delegated.
	creds     *credentials.Credentials
	delegated *credentials.CCache
}

// Flags returns the context's flags (Flag*): what the initiator asked for,
// as the acceptor saw them.
func (c *Context) Flags() uint32 { return c.flags }

// Established reports whether the context is established.
func (c *Context) Established() bool { return c.established }

// Initiator reports whether this side initiated the context.
func (c *Context) Initiator() bool { return c.initiator }

// Credentials returns the acceptor's view of the initiator: who the ticket
// says it is, and the PAC's AD credentials when the ticket has one.
func (c *Context) Credentials() *credentials.Credentials { return c.creds }

// Delegated returns the credentials the initiator delegated (a credential
// cache holding the forwarded TGT, for client.NewFromCCache or Save), or
// nil.
func (c *Context) Delegated() *credentials.CCache { return c.delegated }

// --- Framing (RFC 2743 3.1) ---

// frame returns [APPLICATION 0] { mech OID, TOK_ID, body }.
func frame(tokID uint16, body []byte) []byte {
	o, _ := asn1.Marshal(OID)
	c := append(o, byte(tokID>>8), byte(tokID))
	c = append(c, body...)

	v, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassApplication, Tag: 0, IsCompound: true, Bytes: c})

	return v
}

// unframe returns the TOK_ID and the body of a framed Kerberos token.
func unframe(token []byte) (uint16, []byte, error) {
	var v asn1.RawValue

	rest, err := asn1.Unmarshal(token, &v)
	if err != nil || len(rest) != 0 || v.Class != asn1.ClassApplication || v.Tag != 0 || !v.IsCompound {
		return 0, nil, ErrToken
	}

	var oid asn1.ObjectIdentifier

	body, err := asn1.Unmarshal(v.Bytes, &oid)
	if err != nil {
		return 0, nil, ErrToken
	}

	if !oid.Equal(OID) && !oid.Equal(msOID) {
		return 0, nil, fmt.Errorf("gsskrb5: token of mechanism %v, not Kerberos", oid)
	}

	if len(body) < 2 {
		return 0, nil, ErrToken
	}

	return binary.BigEndian.Uint16(body), body[2:], nil
}

// --- The authenticator's checksum (RFC 4121 4.1.1) ---

// ChannelBindings are the channel bindings of RFC 2744 3.11 (with no
// addresses, as TLS's are): their application data, as
// "tls-server-end-point:" and the certificate's hash, or
// "tls-exporter:" and the exported key (RFC 5929, RFC 9266).
type ChannelBindings struct {
	ApplicationData []byte
}

// hash is the checksum's Bnd: the MD5 of the bindings' encoding (RFC 4121
// 4.1.1.2), zeros for none.
func (b *ChannelBindings) hash() [16]byte {
	if b == nil {
		return [16]byte{}
	}

	e := make([]byte, 20, 20+len(b.ApplicationData))
	binary.LittleEndian.PutUint32(e[16:], uint32(len(b.ApplicationData)))
	e = append(e, b.ApplicationData...)

	return md5.Sum(e)
}

func checksum8003(bnd [16]byte, f uint32, deleg []byte) []byte {
	c := make([]byte, 24, 28+len(deleg))
	binary.LittleEndian.PutUint32(c, 16)
	copy(c[4:20], bnd[:])
	binary.LittleEndian.PutUint32(c[20:], f)

	if len(deleg) > 0 {
		c = append(c, 1, 0, byte(len(deleg)), byte(len(deleg)>>8))
		c = append(c, deleg...)
	}

	return c
}

// --- Establishing a context ---

// InitOptions are an initiator's choices.
type InitOptions struct {
	// Flags asked for (Flag*): FlagInteg and FlagConf are always asked,
	// FlagDeleg only when Delegate is set.
	Flags uint32
	// ChannelBindings, or nil.
	ChannelBindings *ChannelBindings
	// Delegate: forward the client's TGT to the acceptor (FlagDeleg).
	Delegate bool
}

// cfxKey reports whether the key's encryption type has RFC 4121 tokens.
func cfxKey(k types.EncryptionKey) bool {
	switch k.KeyType {
	case etypeID.RC4_HMAC, etypeID.RC4_HMAC_EXP, etypeID.DES3_CBC_SHA1_KD, etypeID.DES3_CBC_SHA1:
		return false
	}

	_, err := crypto.GetEtype(k.KeyType)

	return err == nil
}

func randomSeq() uint64 {
	var b [4]byte

	_, _ = rand.Read(b[:])

	return uint64(binary.BigEndian.Uint32(b[:]) & 0x3fffffff)
}

// NewInitiator starts a context to the service spn ("host/server.example.com"
// or "host@server.example.com"), with a service ticket the client gets (or
// has): it returns the context and the first token, for the acceptor. With
// FlagMutual, the acceptor's answer goes to Continue; without, the context
// is established.
func NewInitiator(cl *client.Client, spn string, opts InitOptions) (*Context, []byte, error) {
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		return nil, nil, err
	}

	if !cfxKey(key) {
		return nil, nil, ErrEncType
	}

	f := opts.Flags | FlagInteg | FlagConf
	f &^= FlagDeleg

	var deleg []byte

	if opts.Delegate {
		deleg, err = forwardedTGTCred(cl, key)
		if err != nil {
			return nil, nil, fmt.Errorf("gsskrb5: delegation: %w", err)
		}

		f |= FlagDeleg
	}

	auth, err := types.NewAuthenticatorAt(cl.Credentials.Domain(), cl.Credentials.CName(), cl.Now())
	if err != nil {
		return nil, nil, err
	}

	et, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, nil, err
	}

	if err = auth.GenerateSeqNumberAndSubKey(key.KeyType, et.GetKeyByteSize()); err != nil {
		return nil, nil, err
	}

	auth.SeqNumber = int64(randomSeq())
	auth.Cksum = types.Checksum{CksumType: checksumGSSAPI, Checksum: checksum8003(opts.ChannelBindings.hash(), f, deleg)}

	ap, err := messages.NewAPReq(tkt, key, auth)
	if err != nil {
		return nil, nil, err
	}

	if f&FlagMutual != 0 {
		types.SetFlag(&ap.APOptions, flags.APOptionMutualRequired)
	}

	b, err := ap.Marshal()
	if err != nil {
		return nil, nil, err
	}

	c := &Context{
		initiator:   true,
		established: f&FlagMutual == 0,
		flags:       f,
		sessionKey:  key,
		key:         auth.SubKey,
		sendSeq:     uint64(auth.SeqNumber),
		recvSeq:     uint64(auth.SeqNumber),
		ctime:       auth.CTime,
		cusec:       auth.Cusec,
	}

	return c, frame(tokAPReq, b), nil
}

// forwardedTGTCred is the KRB-CRED of a forwarded TGT, its part in the
// session key, as MIT sends it for delegation.
func forwardedTGTCred(cl *client.Client, sessionKey types.EncryptionKey) ([]byte, error) {
	tgt, dep, err := cl.GetForwardedTGT()
	if err != nil {
		return nil, err
	}

	info := messages.KrbCredInfo{
		Key:       dep.Key,
		PRealm:    cl.Credentials.Domain(),
		PName:     cl.Credentials.CName(),
		Flags:     dep.Flags,
		AuthTime:  dep.AuthTime,
		StartTime: dep.StartTime,
		EndTime:   dep.EndTime,
		RenewTill: dep.RenewTill,
		SRealm:    tgt.Realm,
		SName:     tgt.SName,
	}

	k, err := messages.NewKRBCred([]messages.Ticket{tgt}, []messages.KrbCredInfo{info}, sessionKey)
	if err != nil {
		return nil, err
	}

	return k.Marshal()
}

// Continue takes the acceptor's answer to an initiator asking for mutual
// authentication: an AP-REP token establishes the context; an error
// token's KRB-ERROR comes back as the error.
func (c *Context) Continue(token []byte) error {
	if !c.initiator || c.established {
		return ErrContext
	}

	id, body, err := unframe(token)
	if err != nil {
		return err
	}

	switch id {
	case tokError:
		var e messages.KRBError
		if err := e.Unmarshal(body); err != nil {
			return ErrToken
		}

		return e
	case tokAPRep:
	default:
		return ErrToken
	}

	var rep messages.APRep
	if err = rep.Unmarshal(body); err != nil {
		return err
	}

	p, err := rep.Decrypt(c.sessionKey, c.ctime, c.cusec)
	if err != nil {
		return err
	}

	// An acceptor subkey replaces the initiator's (RFC 4121 2).
	if len(p.Subkey.KeyValue) > 0 && cfxKey(p.Subkey) {
		c.key = p.Subkey
		c.acceptorSubkey = true
	}

	c.recvSeq = uint64(p.SequenceNumber) & 0xffffffff
	c.established = true

	return nil
}

// AcceptOptions are an acceptor's choices.
type AcceptOptions struct {
	// ChannelBindings the initiator's must match, or nil. An initiator that
	// sent none is accepted, as MIT does by default.
	ChannelBindings *ChannelBindings
}

// Accept checks an initiator's first token with the service settings (its
// keytab, replay cache, clock skew, as service.VerifyAPREQ) and returns
// the context, and the token to send back: the AP-REP when the initiator
// asked for mutual authentication (else nil), or, when the token is
// refused, a KRB-ERROR token with the error.
func Accept(token []byte, s *service.Settings, opts AcceptOptions) (*Context, []byte, error) {
	id, body, err := unframe(token)
	if err != nil {
		return nil, nil, err
	}

	if id != tokAPReq {
		return nil, nil, ErrToken
	}

	var ap messages.APReq
	if err = ap.Unmarshal(body); err != nil {
		return nil, nil, err
	}

	ok, creds, err := service.VerifyAPREQ(&ap, s)
	if !ok || err != nil {
		if err == nil {
			err = errors.New("gsskrb5: AP_REQ not valid")
		}

		return nil, errorToken(err, ap), err
	}

	sum := ap.Authenticator.Cksum
	if sum.CksumType != checksumGSSAPI || len(sum.Checksum) < 24 || binary.LittleEndian.Uint32(sum.Checksum) != 16 {
		err := messages.NewKRBError(ap.Ticket.SName, ap.Ticket.Realm, errorcode.KRB_AP_ERR_INAPP_CKSUM, "not a GSS-API checksum")
		return nil, errorToken(err, ap), err
	}

	var bnd [16]byte

	copy(bnd[:], sum.Checksum[4:20])

	if opts.ChannelBindings != nil && bnd != ([16]byte{}) && bnd != opts.ChannelBindings.hash() {
		err := messages.NewKRBError(ap.Ticket.SName, ap.Ticket.Realm, errorcode.KRB_AP_ERR_BADADDR, "channel bindings do not match")
		return nil, errorToken(err, ap), err
	}

	f := binary.LittleEndian.Uint32(sum.Checksum[20:])

	c := &Context{
		flags:      f,
		sessionKey: ap.Ticket.DecryptedEncPart.Key,
		key:        ap.Ticket.DecryptedEncPart.Key,
		ctime:      ap.Authenticator.CTime,
		cusec:      ap.Authenticator.Cusec,
		creds:      creds,
	}

	if len(ap.Authenticator.SubKey.KeyValue) > 0 {
		c.key = ap.Authenticator.SubKey
	}

	if !cfxKey(c.key) {
		return nil, nil, ErrEncType
	}

	c.sendSeq = uint64(ap.Authenticator.SeqNumber) & 0xffffffff
	c.recvSeq = c.sendSeq

	if f&FlagDeleg != 0 && len(sum.Checksum) >= 28 {
		opt := binary.LittleEndian.Uint16(sum.Checksum[24:])
		n := int(binary.LittleEndian.Uint16(sum.Checksum[26:]))

		if opt != 1 || 28+n > len(sum.Checksum) {
			return nil, nil, ErrToken
		}

		c.delegated, err = delegatedCCache(sum.Checksum[28:28+n], ap)
		if err != nil {
			return nil, nil, fmt.Errorf("gsskrb5: delegated credentials: %w", err)
		}
	}

	var out []byte

	if types.IsFlagSet(&ap.APOptions, flags.APOptionMutualRequired) || f&FlagMutual != 0 {
		et, err := crypto.GetEtype(c.key.KeyType)
		if err != nil {
			return nil, nil, err
		}

		sub, err := types.GenerateEncryptionKey(et)
		if err != nil {
			return nil, nil, err
		}

		seq := randomSeq()

		rep, err := messages.NewAPRep(c.sessionKey, ap.Authenticator.CTime, ap.Authenticator.Cusec, sub, int64(seq))
		if err != nil {
			return nil, nil, err
		}

		b, err := rep.Marshal()
		if err != nil {
			return nil, nil, err
		}

		out = frame(tokAPRep, b)
		c.key = sub
		c.acceptorSubkey = true
		c.sendSeq = seq
	}

	c.established = true

	return c, out, nil
}

// errorToken frames the KRB-ERROR for a refused AP-REQ, or returns nil.
func errorToken(err error, ap messages.APReq) []byte {
	var e messages.KRBError
	if !errors.As(err, &e) {
		e = messages.NewKRBError(ap.Ticket.SName, ap.Ticket.Realm, errorcode.KRB_AP_ERR_MSG_TYPE, err.Error())
	}

	e.MsgType = msgtype.KRB_ERROR

	b, merr := e.Marshal()
	if merr != nil {
		return nil
	}

	return frame(tokError, b)
}

// delegatedCCache reads the KRB-CRED of delegated credentials, its part in
// the session key or the initiator's subkey (or in the clear, as some
// send it), into a credential cache.
func delegatedCCache(b []byte, ap messages.APReq) (*credentials.CCache, error) {
	var k messages.KRBCred
	if err := k.Unmarshal(b); err != nil {
		return nil, err
	}

	if k.EncPart.EType == 0 {
		if err := k.DecryptedEncPart.Unmarshal(k.EncPart.Cipher); err != nil {
			return nil, err
		}
	} else if err := k.DecryptEncPart(ap.Ticket.DecryptedEncPart.Key); err != nil {
		if len(ap.Authenticator.SubKey.KeyValue) == 0 || k.DecryptEncPart(ap.Authenticator.SubKey) != nil {
			return nil, err
		}
	}

	if len(k.DecryptedEncPart.TicketInfo) != len(k.Tickets) || len(k.Tickets) == 0 {
		return nil, errors.New("KRB_CRED's tickets and their infos do not pair")
	}

	client := k.DecryptedEncPart.TicketInfo[0]
	if client.PName.NameType == 0 && len(client.PName.NameString) == 0 {
		client.PName = ap.Ticket.DecryptedEncPart.CName
		client.PRealm = ap.Ticket.DecryptedEncPart.CRealm
	}

	cc := credentials.NewV4CCache(client.PName, client.PRealm)

	for i, info := range k.DecryptedEncPart.TicketInfo {
		tb, err := k.Tickets[i].Marshal()
		if err != nil {
			return nil, err
		}

		sname, srealm := info.SName, info.SRealm
		if len(sname.NameString) == 0 {
			sname, srealm = k.Tickets[i].SName, k.Tickets[i].Realm
		}

		if sname.NameType == 0 {
			sname.NameType = nametype.KRB_NT_SRV_INST
		}

		cc.AddCredential(&credentials.Credential{
			Client:      credentials.Principal{Realm: client.PRealm, PrincipalName: client.PName},
			Server:      credentials.Principal{Realm: srealm, PrincipalName: sname},
			Key:         info.Key,
			AuthTime:    info.AuthTime,
			StartTime:   info.StartTime,
			EndTime:     info.EndTime,
			RenewTill:   info.RenewTill,
			TicketFlags: info.Flags,
			Ticket:      tb,
		})
	}

	return cc, nil
}

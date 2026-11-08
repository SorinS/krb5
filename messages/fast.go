package messages

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/SorinS/krb5/asn1tools"
	"github.com/SorinS/krb5/crypto"
	"github.com/SorinS/krb5/iana"
	"github.com/SorinS/krb5/iana/asn1apptag"
	"github.com/SorinS/krb5/iana/keyusage"
	"github.com/SorinS/krb5/iana/msgtype"
	"github.com/SorinS/krb5/iana/patype"
	"github.com/SorinS/krb5/types"
)

// FAST (RFC 6113), the client's side. A KDC request travels inside an
// armor: its real padata and body are encrypted under the armor key, and
// the KDC's reply comes back inside it too, its errors authenticated and
// its reply key strengthened.
//
// The armor key. In an AS exchange it comes from a TGT the client already
// has (a host's, as MIT's kinit -T takes it; Windows' machine account): an
// AP-REQ for that TGT with a fresh subkey, and
// KRB-FX-CF2(subkey, "subkeyarmor", session key, "ticketarmor"). In a TGS
// exchange the TGT the request is made with is the armor (implicit armor):
// the same function of the authenticator's subkey and the TGT's session
// key; or another TGT armors it as well (explicit armor), as Windows does
// with the computer's TGT for compound identity.

// FX_FAST_ARMOR_AP_REQUEST is the one armor type (RFC 6113 5.4.1).
const FX_FAST_ARMOR_AP_REQUEST = 1

// ErrFAST is a FAST reply or error that does not check: not under the
// armor key, not for our request, or without the parts it must have.
var ErrFAST = errors.New("FAST reply does not check")

// KrbFastArmor is RFC 6113's KrbFastArmor.
type KrbFastArmor struct {
	ArmorType  int32  `asn1:"explicit,tag:0"`
	ArmorValue []byte `asn1:"explicit,tag:1"`
}

// KrbFastArmoredReq is RFC 6113's KrbFastArmoredReq.
type KrbFastArmoredReq struct {
	Armor       KrbFastArmor        `asn1:"explicit,optional,tag:0"`
	ReqChecksum types.Checksum      `asn1:"explicit,tag:1"`
	EncFastReq  types.EncryptedData `asn1:"explicit,tag:2"`
}

// KrbFastFinished is RFC 6113's KrbFastFinished.
type KrbFastFinished struct {
	Timestamp      time.Time           `asn1:"generalized,explicit,tag:0"`
	Usec           int                 `asn1:"explicit,tag:1"`
	CRealm         string              `asn1:"general,explicit,tag:2"`
	CName          types.PrincipalName `asn1:"explicit,tag:3"`
	TicketChecksum types.Checksum      `asn1:"explicit,tag:4"`
}

// KrbFastResponse is RFC 6113's KrbFastResponse.
type KrbFastResponse struct {
	PAData        types.PADataSequence `asn1:"explicit,tag:0"`
	StrengthenKey types.EncryptionKey  `asn1:"explicit,optional,tag:1"`
	Finished      KrbFastFinished      `asn1:"explicit,optional,tag:2"`
	Nonce         int64                `asn1:"explicit,tag:3"`
}

type krbFastArmoredRep struct {
	EncFastRep types.EncryptedData `asn1:"explicit,tag:0"`
}

// HasStrengthenKey is whether the response carries a strengthen key.
func (r *KrbFastResponse) HasStrengthenKey() bool {
	return r.StrengthenKey.KeyType != 0 && len(r.StrengthenKey.KeyValue) > 0
}

// HasFinished is whether the response carries its finished part.
func (r *KrbFastResponse) HasFinished() bool {
	return r.Finished.TicketChecksum.CksumType != 0
}

// FASTState is one armored exchange: the armor key and the armor to send
// (none for a TGS request's implicit armor).
type FASTState struct {
	ArmorKey types.EncryptionKey
	Armor    *KrbFastArmor
}

// An Armor is the TGT that armors a request: krbtgt/REALM@REALM, its
// session key, and its client.
type Armor struct {
	Ticket     Ticket
	SessionKey types.EncryptionKey
	CName      types.PrincipalName
	CRealm     string
}

// apReqArmor is an AP-REQ for the armor TGT with a new subkey of its
// session key's type and no checksum (MIT's KDC refuses armor without a
// subkey), at the time now; and the subkey.
func apReqArmor(a Armor, now time.Time) (KrbFastArmor, types.EncryptionKey, error) {
	subkey, err := crypto.RandomKey(a.SessionKey.KeyType)
	if err != nil {
		return KrbFastArmor{}, subkey, err
	}

	auth, err := types.NewAuthenticatorAt(a.CRealm, a.CName, now)
	if err != nil {
		return KrbFastArmor{}, subkey, err
	}

	auth.SubKey = subkey

	ap, err := NewAPReqUsage(a.Ticket, a.SessionKey, auth, keyusage.AP_REQ_AUTHENTICATOR)
	if err != nil {
		return KrbFastArmor{}, subkey, err
	}

	b, err := ap.Marshal()
	if err != nil {
		return KrbFastArmor{}, subkey, err
	}

	return KrbFastArmor{ArmorType: FX_FAST_ARMOR_AP_REQUEST, ArmorValue: b}, subkey, nil
}

// NewFASTArmorAS is the armor of an AS exchange from a TGT for the realm
// asked, at the time now (the KDC's).
func NewFASTArmorAS(a Armor, now time.Time) (FASTState, error) {
	armor, subkey, err := apReqArmor(a, now)
	if err != nil {
		return FASTState{}, err
	}

	key, err := crypto.CF2(subkey, "subkeyarmor", a.SessionKey, "ticketarmor")
	if err != nil {
		return FASTState{}, err
	}

	return FASTState{ArmorKey: key, Armor: &armor}, nil
}

// NewFASTArmorTGS is the implicit armor of a TGS exchange: from the
// authenticator's subkey and the TGT's session key.
func NewFASTArmorTGS(subkey, sessionKey types.EncryptionKey) (FASTState, error) {
	key, err := crypto.CF2(subkey, "subkeyarmor", sessionKey, "ticketarmor")
	if err != nil {
		return FASTState{}, err
	}

	return FASTState{ArmorKey: key}, nil
}

// NewFASTArmorTGSExplicit is the explicit armor of a TGS exchange (RFC
// 6113 5.4.1.1): the armor of an AS exchange from device, a TGT of the
// realm's other than the one the request is made with (a computer's, for
// Active Directory's compound identity), and the key
// KRB-FX-CF2(that armor's key, "explicitarmor", subkey, "tgsarmor"). MIT's
// KDC refuses it; Active Directory's takes it.
func NewFASTArmorTGSExplicit(device Armor, subkey types.EncryptionKey, now time.Time) (FASTState, error) {
	st, err := NewFASTArmorAS(device, now)
	if err != nil {
		return st, err
	}

	st.ArmorKey, err = crypto.CF2(st.ArmorKey, "explicitarmor", subkey, "tgsarmor")

	return st, err
}

// explicit is DER for [tag] EXPLICIT around b.
func explicit(tag int, b []byte) ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: b})
}

// Wrap is the armored request: inner (the request's real padata) and the
// body inside the armor; outside, outer (a TGS request's PA-TGS-REQ) and
// then PA-FX-FAST, and the same body. The request's checksum is over
// checksummed: the body's DER for an AS request, the PA-TGS-REQ's AP-REQ
// for a TGS request (RFC 6113 5.4.2). The result is the request to send,
// with its application tag (msgType's).
func (st *FASTState) Wrap(msgType int, inner, outer types.PADataSequence, body KDCReqBody, checksummed []byte) ([]byte, error) {
	bodyDER, err := body.Marshal()
	if err != nil {
		return nil, err
	}

	// KrbFastReq: fast-options [0] (none), padata [1], req-body [2].
	opts, err := asn1.Marshal(types.NewKrbFlags())
	if err != nil {
		return nil, err
	}

	if inner == nil {
		inner = types.PADataSequence{}
	}

	pa, err := asn1.Marshal(inner, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	if err != nil {
		return nil, err
	}

	var fr []byte

	for i, part := range [][]byte{opts, pa, bodyDER} {
		e, err := explicit(i, part)
		if err != nil {
			return nil, err
		}

		fr = append(fr, e...)
	}

	frDER, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: fr})
	if err != nil {
		return nil, err
	}

	enc, err := crypto.GetEncryptedData(frDER, st.ArmorKey, keyusage.KEY_USAGE_FAST_ENC, 0)
	if err != nil {
		return nil, err
	}

	et, err := crypto.GetEtype(st.ArmorKey.KeyType)
	if err != nil {
		return nil, err
	}

	ck, err := et.GetChecksumHash(st.ArmorKey.KeyValue, checksummed, keyusage.KEY_USAGE_FAST_REQ_CHKSUM)
	if err != nil {
		return nil, err
	}

	ar := KrbFastArmoredReq{ReqChecksum: types.Checksum{CksumType: et.GetHashID(), Checksum: ck}, EncFastReq: enc}
	if st.Armor != nil {
		ar.Armor = *st.Armor
	}

	arDER, err := asn1.Marshal(ar)
	if err != nil {
		return nil, err
	}

	// PA-FX-FAST-REQUEST ::= CHOICE { armored-data [0] KrbFastArmoredReq }.
	fx, err := explicit(0, arDER)
	if err != nil {
		return nil, err
	}

	padata := append(append(types.PADataSequence{}, outer...), types.PAData{PADataType: patype.PA_FX_FAST, PADataValue: fx})
	m := marshalKDCReq{PVNO: iana.PVNO, MsgType: msgType, PAData: padata,
		ReqBody: asn1.RawValue{Class: asn1.ClassContextSpecific, IsCompound: true, Tag: 4, Bytes: bodyDER}}

	b, err := asn1.Marshal(m, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	if err != nil {
		return nil, err
	}

	tag := asn1apptag.ASREQ
	if msgType == msgtype.KRB_TGS_REQ {
		tag = asn1apptag.TGSREQ
	}

	return asn1tools.AddASNAppTag(b, tag), nil
}

// derUnpadded is a decrypted SEQUENCE without the zeros DES3 pads it with
// to its block.
func derUnpadded(plain []byte) []byte {
	var rv asn1.RawValue

	rest, err := asn1.Unmarshal(plain, &rv)
	if err != nil {
		return plain
	}

	for _, b := range rest {
		if b != 0 {
			return plain
		}
	}

	return plain[:len(plain)-len(rest)]
}

// Response is the FAST response in padata (a reply's, or an error's
// e-data): ErrFAST if there is none, it does not decrypt under the armor
// key, or its nonce is not the request's.
func (st *FASTState) Response(padata types.PADataSequence, nonce int) (KrbFastResponse, error) {
	var r KrbFastResponse

	for _, pa := range padata {
		if pa.PADataType != patype.PA_FX_FAST {
			continue
		}

		// PA-FX-FAST-REPLY ::= CHOICE { armored-data [0] KrbFastArmoredRep }.
		var choice asn1.RawValue
		if _, err := asn1.Unmarshal(pa.PADataValue, &choice); err != nil || choice.Class != asn1.ClassContextSpecific || choice.Tag != 0 {
			return r, ErrFAST
		}

		var rep krbFastArmoredRep
		if _, err := asn1.Unmarshal(choice.Bytes, &rep); err != nil {
			return r, ErrFAST
		}

		plain, err := crypto.DecryptEncPart(rep.EncFastRep, st.ArmorKey, keyusage.KEY_USAGE_FAST_REP)
		if err != nil {
			return r, ErrFAST
		}

		if _, err := asn1.Unmarshal(derUnpadded(plain), &r, asn1.WithUnmarshalAllowTypeGeneralString(true)); err != nil {
			return r, fmt.Errorf("%w: %v", ErrFAST, err)
		}

		if uint32(r.Nonce) != uint32(nonce) {
			return r, fmt.Errorf("%w: nonce", ErrFAST)
		}

		return r, nil
	}

	return r, fmt.Errorf("%w: no PA-FX-FAST", ErrFAST)
}

// Reply is the FAST response of an AS or TGS reply: as Response, and its
// finished part there with a checksum (keyed, under the armor key) of the
// reply's ticket.
func (st *FASTState) Reply(padata types.PADataSequence, ticket Ticket, nonce int) (KrbFastResponse, error) {
	r, err := st.Response(padata, nonce)
	if err != nil {
		return r, err
	}

	if !r.HasFinished() {
		return r, fmt.Errorf("%w: no finished part", ErrFAST)
	}

	tb, err := ticket.Marshal()
	if err != nil {
		return r, err
	}

	et, err := crypto.GetChksumEtype(r.Finished.TicketChecksum.CksumType)
	if err != nil || et.GetETypeID() != st.ArmorKey.KeyType {
		return r, fmt.Errorf("%w: ticket checksum type", ErrFAST)
	}

	if !et.VerifyChecksum(st.ArmorKey.KeyValue, tb, r.Finished.TicketChecksum.Checksum, keyusage.KEY_USAGE_FAST_FINISHED) {
		return r, fmt.Errorf("%w: ticket checksum", ErrFAST)
	}

	return r, nil
}

// ReplyKey is the reply key strengthened if the KDC sent a strengthen key:
// KRB-FX-CF2(strengthen key, "strengthenkey", reply key, "replykey").
func (r *KrbFastResponse) ReplyKey(key types.EncryptionKey) (types.EncryptionKey, error) {
	if !r.HasStrengthenKey() {
		return key, nil
	}

	return crypto.CF2(r.StrengthenKey, "strengthenkey", key, "replykey")
}

// Error is the error inside an armored KRB-ERROR: the KRB-ERROR in the FAST
// response's PA-FX-ERROR, and the response's other padata (ETYPE-INFO2,
// PA-FX-COOKIE, the methods the KDC offers). ErrFAST if the outer error's
// e-data holds no FAST response that checks.
func (st *FASTState) Error(outer KRBError, nonce int) (KRBError, types.PADataSequence, error) {
	var pas types.PADataSequence
	if len(outer.EData) == 0 || pas.Unmarshal(outer.EData) != nil {
		return outer, nil, fmt.Errorf("%w: error without FAST e-data", ErrFAST)
	}

	r, err := st.Response(pas, nonce)
	if err != nil {
		return outer, nil, err
	}

	var (
		inner KRBError
		found bool
		hints types.PADataSequence
	)

	for _, pa := range r.PAData {
		if pa.PADataType == patype.PA_FX_ERROR && !found {
			if err := inner.Unmarshal(pa.PADataValue); err != nil {
				return outer, nil, fmt.Errorf("%w: PA-FX-ERROR: %v", ErrFAST, err)
			}

			found = true

			continue
		}

		hints = append(hints, pa)
	}

	if !found {
		return outer, nil, fmt.Errorf("%w: no PA-FX-ERROR", ErrFAST)
	}

	return inner, hints, nil
}

// EncryptedChallenge is PA-ENCRYPTED-CHALLENGE's value (RFC 6113 5.4.6):
// the time (PA-ENC-TS-ENC) under
// KRB-FX-CF2(armor key, "clientchallengearmor", key, "challengelongterm").
func (st *FASTState) EncryptedChallenge(key types.EncryptionKey, now time.Time) ([]byte, error) {
	ck, err := crypto.CF2(st.ArmorKey, "clientchallengearmor", key, "challengelongterm")
	if err != nil {
		return nil, err
	}

	ts, err := types.GetPAEncTSEncAsnMarshalledAt(now)
	if err != nil {
		return nil, err
	}

	ed, err := crypto.GetEncryptedData(ts, ck, keyusage.KEY_USAGE_ENC_CHALLENGE_CLIENT, 0)
	if err != nil {
		return nil, err
	}

	return ed.Marshal()
}

// CheckKDCChallenge checks the KDC's encrypted challenge in a reply's
// padata: its time under the KDC challenge key ("kdcchallengearmor"),
// which only a KDC that knows the client's key can make.
func (st *FASTState) CheckKDCChallenge(key types.EncryptionKey, padata types.PADataSequence) error {
	for _, pa := range padata {
		if pa.PADataType != patype.PA_ENCRYPTED_CHALLENGE {
			continue
		}

		var ed types.EncryptedData
		if err := ed.Unmarshal(pa.PADataValue); err != nil {
			return fmt.Errorf("%w: KDC's encrypted challenge: %v", ErrFAST, err)
		}

		ck, err := crypto.CF2(st.ArmorKey, "kdcchallengearmor", key, "challengelongterm")
		if err != nil {
			return err
		}

		plain, err := crypto.DecryptEncPart(ed, ck, keyusage.KEY_USAGE_ENC_CHALLENGE_KDC)
		if err != nil {
			return fmt.Errorf("%w: KDC's encrypted challenge: %v", ErrFAST, err)
		}

		var ts types.PAEncTSEnc
		if err := ts.Unmarshal(derUnpadded(plain)); err != nil {
			return fmt.Errorf("%w: KDC's encrypted challenge: %v", ErrFAST, err)
		}

		return nil
	}

	return fmt.Errorf("%w: no KDC encrypted challenge", ErrFAST)
}

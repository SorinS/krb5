package client

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/krberror"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/pkinit"
	"github.com/go-krb5/krb5/spake"
	"github.com/go-krb5/krb5/types"
)

// ASExchange performs an AS exchange for the client to retrieve a TGT.
//
// Pre-authentication is added when the KDC asks for it. With kdc_timesync
// (MIT's default), a KRB_AP_ERR_SKEW error from the KDC sets the client's
// clock offset from the error's time and the request is made once more, and
// a reply sets the offset from its auth time, as MIT does.
//
// With a FAST armor for the realm (FASTArmor), every request is armored
// (RFC 6113): the KDC's errors come authenticated, encrypted challenge
// replaces the encrypted timestamp when the KDC offers it, and the reply
// key is strengthened.
func (cl *Client) ASExchange(realm string, ASReq messages.ASReq, referral int) (messages.ASRep, error) {
	if ok, err := cl.IsConfigured(); !ok {
		return messages.ASRep{}, krberror.Errorf(err, krberror.ConfigError, "AS Exchange cannot be performed")
	}

	armor, err := cl.armorFor(realm)
	if err != nil {
		return messages.ASRep{}, krberror.Errorf(err, krberror.ConfigError, "AS Exchange cannot be performed")
	}

	x := &asExchange{cl: cl, realm: realm, req: ASReq, armor: armor}

	if cl.pkinit != nil || cl.anonymous {
		x.pk = true
		x.pkMin = pkinit.GroupFromConfig(cl.Config, realm)
		x.pkGroup = x.pkMin
		x.pkKDFs = pkinit.KDFsFromConfig(cl.Config, realm)
	}

	// The request's own padata (PA-PAC-OPTIONS, ...); pre-authentication
	// and PA-REQ-ENC-PA-REP are added to each request.
	for _, pa := range ASReq.PAData {
		switch pa.PADataType {
		case patype.PA_ENC_TIMESTAMP, patype.PA_REQ_ENC_PA_REP, patype.PA_ENCRYPTED_CHALLENGE, patype.PA_FX_COOKIE:
		default:
			x.base = append(x.base, pa)
		}
	}

	// A KDC that wanted pre-authentication before: the timestamp in the
	// first request, by what it said then (unarmored; armored, the KDC's
	// offer decides between timestamp and challenge).
	if cl.settings.assumePreAuthentication && armor == nil && !x.pk {
		if err := x.keyFromHints(cl.settings.preAuthHints()); err != nil {
			return messages.ASRep{}, krberror.Errorf(err, krberror.EncryptingError, "AS Exchange Error: failed to make the pre-authentication key")
		}

		x.storedKey = true
	}

	return x.run(referral)
}

// asExchange is one AS exchange under way.
type asExchange struct {
	cl    *Client
	realm string
	req   messages.ASReq
	base  types.PADataSequence // The request's own padata.
	armor *messages.Armor

	// The pre-authentication key (the client's long-term key of the type
	// the KDC said), whether it came from an earlier exchange's hints, and
	// whether the KDC offered encrypted challenge.
	key       types.EncryptionKey
	kvno      int
	haveKey   bool
	storedKey bool
	challenge bool

	cookie []byte // The KDC's PA-FX-COOKIE, sent back.

	// SPAKE: the client's state, what the next request sends (spakeNone,
	// the support message, or the response to a challenge), the support
	// message, and the reply key K'[0] once a response is sent.
	spake        *spake.Client
	spakeNext    int
	spakeSupport []byte
	spakeKey     types.EncryptionKey

	// PKINIT: whether this exchange uses it (an identity, or anonymous);
	// whether the next request carries PA-PK-AS-REQ (else an empty
	// PA-AS-FRESHNESS, asking for a token); the group (from
	// pkinit_dh_min_bits) and the least taken; the KDC's freshness token;
	// one retry each for another group and a new token; the KDFs offered;
	// what the reply is checked with.
	pk           bool
	pkNext       bool
	pkGroup      pkinit.Group
	pkMin        pkinit.Group
	pkFresh      []byte
	pkGroupRetry bool
	pkFreshRetry bool
	pkKDFs       []pkinit.KDF
	pkReq        *pkinit.Request
}

const (
	spakeNone = iota
	spakeSendSupport
	spakeSendResponse
)

// spakeGroups are the SPAKE groups the client takes (MIT's
// spake_preauth_groups; edwards25519 when not set).
func (cl *Client) spakeGroups() []int32 {
	if v, ok := cl.Config.LibDefaults.Values["spake_preauth_groups"]; ok && len(v) > 0 {
		return spake.GroupsNamed(strings.Join(v, " "))
	}

	return []int32{spake.Edwards25519}
}

// spakeOffered acts on the KDC's PA-SPAKE offer in its PREAUTH_REQUIRED
// (the key known): our support message for an empty offer, or our
// response to an optimistic challenge in a group we take, or our groups
// for a challenge in another. False when SPAKE is not offered, or the
// client takes no group, or the offer cannot be read.
func (x *asExchange) spakeOffered(hints types.PADataSequence) (bool, error) {
	groups := x.cl.spakeGroups()
	if len(groups) == 0 {
		return false, nil
	}

	for _, pa := range hints {
		if pa.PADataType != patype.PA_SPAKE {
			continue
		}

		x.spake = spake.NewClient(groups)

		var m spake.Message
		if len(pa.PADataValue) > 0 {
			if err := m.Unmarshal(pa.PADataValue); err != nil || m.Choice != spake.ChoiceChallenge {
				return false, nil
			}

			if x.spake.Takes(m.Group) {
				if err := x.spake.Challenge(pa.PADataValue, x.key, nil); err != nil {
					return false, err
				}

				x.spakeNext = spakeSendResponse

				return true, nil
			}
		}

		b, err := x.spake.Support()
		if err != nil {
			return false, err
		}

		x.spakeSupport, x.spakeNext = b, spakeSendSupport

		return true, nil
	}

	return false, nil
}

// keyFromHints makes the pre-authentication key from the KDC's hints
// (ETYPE-INFO2, ETYPE-INFO, PA-PW-SALT): the first type it lists that we
// asked for and have a key of.
func (x *asExchange) keyFromHints(hints types.PADataSequence) error {
	ids := preAuthETypes(hints)
	if len(ids) == 0 {
		ids = x.req.ReqBody.EType
	}

	var lastErr error

	for _, id := range ids {
		if !slices.Contains(x.req.ReqBody.EType, id) {
			continue
		}

		k, kvno, err := x.cl.keyFor(id, x.req.ReqBody.CName, x.realm, hints)
		if err != nil {
			lastErr = err
			continue
		}

		x.key, x.kvno, x.haveKey = k, kvno, true

		return nil
	}

	if lastErr == nil {
		lastErr = errors.New("no encryption type in common with the KDC's pre-authentication hints")
	}

	return lastErr
}

// keyFor is the client's long-term key of the type, a password's by the
// salt in hints.
func (cl *Client) keyFor(etypeID int32, cname types.PrincipalName, realm string, hints types.PADataSequence) (types.EncryptionKey, int, error) {
	if cl.Credentials.HasKeytab() {
		return cl.Credentials.Keytab().GetEncryptionKey(cname, realm, 0, etypeID)
	}

	if cl.Credentials.HasPassword() {
		k, _, err := crypto.GetKeyFromPassword(cl.Credentials.Password(), cname, realm, etypeID, hints)
		return k, 0, err
	}

	return types.EncryptionKey{}, 0, errors.New("credential has neither keytab or password to generate key")
}

// preAuthETypes are the types ETYPE-INFO2 (or else ETYPE-INFO) lists, in
// the KDC's order.
func preAuthETypes(hints types.PADataSequence) []int32 {
	var info2, info []int32

	for _, pa := range hints {
		switch pa.PADataType {
		case patype.PA_ETYPE_INFO2:
			if e, err := pa.GetETypeInfo2(); err == nil {
				for _, i := range e {
					info2 = append(info2, i.EType)
				}
			}
		case patype.PA_ETYPE_INFO:
			if e, err := pa.GetETypeInfo(); err == nil {
				for _, i := range e {
					info = append(info, i.EType)
				}
			}
		}
	}

	if len(info2) > 0 {
		return info2
	}

	return info
}

// padata is the padata of the next request: the request's own, the
// pre-authentication (encrypted challenge inside FAST when the KDC offered
// it, else the encrypted timestamp), the KDC's cookie, and the ask for the
// request's checksum in the reply.
func (x *asExchange) padata(st *messages.FASTState, bodyDER []byte) (types.PADataSequence, error) {
	pas := append(types.PADataSequence{}, x.base...)
	now := x.cl.Now()

	switch {
	case x.pk && x.pkNext:
		// A new key pair each time, the AuthPack bound to the body.
		dh, err := pkinit.NewDHKey(x.pkGroup)
		if err != nil {
			return nil, err
		}

		ap, err := pkinit.AuthPack(now, x.req.ReqBody.Nonce, bodyDER, x.pkFresh, dh, x.pkKDFs)
		if err != nil {
			return nil, err
		}

		v, err := pkinit.PAPKASReq(ap, x.cl.pkinit)
		if err != nil {
			return nil, err
		}

		x.pkReq = &pkinit.Request{DH: dh, Nonce: x.req.ReqBody.Nonce, KDFs: x.pkKDFs}
		pas = append(pas, types.PAData{PADataType: patype.PA_PK_AS_REQ, PADataValue: v})
	case x.pk:
		// An empty PA-AS-FRESHNESS asks for a freshness token (RFC 8070).
		pas = append(pas, types.PAData{PADataType: patype.PA_AS_FRESHNESS, PADataValue: []byte{}})
	case x.spakeNext == spakeSendSupport:
		pas = append(pas, types.PAData{PADataType: patype.PA_SPAKE, PADataValue: x.spakeSupport})
	case x.spakeNext == spakeSendResponse:
		// The response's keys are bound to the request's body.
		v, k0, err := x.spake.Response(bodyDER)
		if err != nil {
			return nil, err
		}

		x.spakeKey = k0
		pas = append(pas, types.PAData{PADataType: patype.PA_SPAKE, PADataValue: v})
	case x.haveKey && st != nil && x.challenge:
		v, err := st.EncryptedChallenge(x.key, now)
		if err != nil {
			return nil, err
		}

		pas = append(pas, types.PAData{PADataType: patype.PA_ENCRYPTED_CHALLENGE, PADataValue: v})
	case x.haveKey:
		v, err := encryptedTimestamp(x.key, x.kvno, now)
		if err != nil {
			return nil, err
		}

		pas = append(pas, types.PAData{PADataType: patype.PA_ENC_TIMESTAMP, PADataValue: v})
	}

	if x.cookie != nil {
		pas = append(pas, types.PAData{PADataType: patype.PA_FX_COOKIE, PADataValue: x.cookie})
	}

	// Ask for the request's checksum in the reply (RFC 6806 11), which
	// lets a canonicalized reply be trusted.
	if !x.cl.settings.DisablePAFXFAST() {
		pas = append(pas, types.PAData{PADataType: patype.PA_REQ_ENC_PA_REP})
	}

	return pas, nil
}

// encryptedTimestamp is PA-ENC-TIMESTAMP's value: the time now in key.
func encryptedTimestamp(key types.EncryptionKey, kvno int, now time.Time) ([]byte, error) {
	ts, err := types.GetPAEncTSEncAsnMarshalledAt(now)
	if err != nil {
		return nil, err
	}

	ed, err := crypto.GetEncryptedData(ts, key, keyusage.AS_REQ_PA_ENC_TIMESTAMP, kvno)
	if err != nil {
		return nil, err
	}

	return ed.Marshal()
}

func (x *asExchange) run(referral int) (messages.ASRep, error) {
	cl := x.cl

	var skewFixed, retriedStale bool

	for attempt := 0; attempt < 8; attempt++ {
		var st *messages.FASTState

		if x.armor != nil {
			s, err := messages.NewFASTArmorAS(*x.armor, cl.Now())
			if err != nil {
				return messages.ASRep{}, krberror.Errorf(err, krberror.EncryptingError, "AS Exchange Error: failed to make the FAST armor")
			}

			st = &s
		}

		bodyDER, err := x.req.ReqBody.Marshal()
		if err != nil {
			return messages.ASRep{}, krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed marshaling the AS_REQ body")
		}

		pas, err := x.padata(st, bodyDER)
		if err != nil {
			return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: issue with setting PAData on AS_REQ")
		}

		req := x.req
		req.PAData = pas

		var sent []byte

		if st != nil {
			bodyDER, err := req.ReqBody.Marshal()
			if err == nil {
				sent, err = st.Wrap(msgtype.KRB_AS_REQ, pas, nil, req.ReqBody, bodyDER)
			}

			if err != nil {
				return messages.ASRep{}, krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed marshaling the armored AS_REQ")
			}
		} else if sent, err = req.Marshal(); err != nil {
			return messages.ASRep{}, krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed marshaling AS_REQ")
		}

		rb, err := cl.sendToKDC(sent, x.realm)
		if err == nil {
			return x.reply(req, sent, rb, st)
		}

		outer, ok := err.(messages.KRBError)
		if !ok {
			return messages.ASRep{}, krberror.Errorf(err, krberror.NetworkingError, "AS Exchange Error: failed sending AS_REQ to KDC")
		}

		e := outer

		var hints types.PADataSequence

		if st != nil {
			inner, h, ferr := st.Error(outer, req.ReqBody.Nonce)
			if ferr != nil {
				// The KDC could not read our armor, so its error is in the
				// clear. Skew alone is acted on (MIT does too): the armor's
				// authenticator is checked against the KDC's clock; the
				// next request is armored all the same.
				if outer.ErrorCode == errorcode.KRB_AP_ERR_SKEW && !skewFixed && cl.Config.LibDefaults.KDCTimeSync == 1 {
					cl.syncTime(outer.STime, outer.Susec)
					skewFixed = true

					continue
				}

				return messages.ASRep{}, krberror.Errorf(err, krberror.KDCError, "AS Exchange Error: kerberos error response from KDC (%v)", errFASTRequired)
			}

			e, hints = inner, h
		} else if len(outer.EData) > 0 {
			_ = hints.Unmarshal(outer.EData)
		}

		// The KDC's cookie goes back in the next request (RFC 6113 5.2).
		for _, pa := range hints {
			if pa.PADataType == patype.PA_FX_COOKIE {
				x.cookie = pa.PADataValue
			}
		}

		if x.pk {
			if done, err := x.pkError(e, hints); err != nil {
				return messages.ASRep{}, err
			} else if done {
				continue
			}
		}

		switch {
		case e.ErrorCode == errorcode.KDC_ERR_PREAUTH_REQUIRED && !x.pk && (!x.haveKey || x.storedKey && !retriedStale):
			if x.storedKey {
				retriedStale = true
			}

			x.storedKey = false

			if err := x.keyFromHints(hints); err != nil {
				return messages.ASRep{}, krberror.Errorf(err, krberror.EncryptingError, "AS Exchange Error: failed setting AS_REQ PAData for pre-authentication required")
			}

			x.challenge = st != nil && hints.Contains(patype.PA_ENCRYPTED_CHALLENGE)

			// SPAKE when the KDC offers it.
			if ok, err := x.spakeOffered(hints); err != nil {
				return messages.ASRep{}, krberror.Errorf(err, krberror.EncryptingError, "AS Exchange Error: SPAKE")
			} else if ok {
				continue
			}

			// From now on assume this client will need to do this
			// pre-auth: its ETYPE-INFO2 (the salt) serves later logins
			// too.
			if st == nil {
				cl.settings.assumePreAuthentication = true
				pe := e
				cl.settings.preAuthError = &pe
			}

			// MIT's disable_encrypted_timestamp: never the timestamp,
			// which anyone who sees it can guess the password from.
			if !x.challenge && cl.disableEncryptedTimestamp(x.realm) {
				return messages.ASRep{}, krberror.Errorf(e, krberror.KDCError, "AS Exchange Error: the KDC offers no pre-authentication but the encrypted timestamp, which is disabled")
			}
		case e.ErrorCode == errorcode.KDC_ERR_MORE_PREAUTH_DATA_REQUIRED && x.spakeNext == spakeSendSupport:
			// SPAKE's challenge, after our support message: in a group we
			// offered (no second support message, as MIT).
			var ch []byte

			for _, pa := range hints {
				if pa.PADataType == patype.PA_SPAKE {
					ch = pa.PADataValue
				}
			}

			if err := x.spake.Challenge(ch, x.key, nil); err != nil {
				return messages.ASRep{}, krberror.Errorf(err, krberror.KDCError, "AS Exchange Error: the KDC's SPAKE challenge")
			}

			x.spakeNext = spakeSendResponse
		case e.ErrorCode == errorcode.KDC_ERR_PREAUTH_FAILED && x.spakeNext == spakeSendSupport:
			// Our support message refused (no group in common): the other
			// pre-authentication the KDC offered. After our response there
			// is no going back to them (the draft's 10.5).
			x.spakeNext = spakeNone

			if !x.challenge && cl.disableEncryptedTimestamp(x.realm) {
				return messages.ASRep{}, krberror.Errorf(e, krberror.KDCError, "AS Exchange Error: no SPAKE group in common, and the encrypted timestamp is disabled")
			}
		case e.ErrorCode == errorcode.KDC_ERR_PREAUTH_FAILED && x.storedKey && !retriedStale:
			// The key of an earlier login's hints, stale: ask again.
			retriedStale = true
			x.storedKey, x.haveKey = false, false
		case e.ErrorCode == errorcode.KRB_AP_ERR_SKEW && !skewFixed && cl.Config.LibDefaults.KDCTimeSync == 1:
			cl.syncTime(e.STime, e.Susec)
			skewFixed = true
		case e.ErrorCode == errorcode.KDC_ERR_WRONG_REALM:
			// Client referral https://tools.ietf.org/html/rfc6806.html#section-7
			if referral > 5 {
				return messages.ASRep{}, krberror.Errorf(e, krberror.KRBMsgError, "maximum number of client referrals exceeded")
			}

			return cl.ASExchange(e.CRealm, x.req, referral+1)
		default:
			return messages.ASRep{}, krberror.Errorf(e, krberror.KDCError, "AS Exchange Error: kerberos error response from KDC")
		}
	}

	return messages.ASRep{}, krberror.New(krberror.KDCError, "AS Exchange Error: too many rounds with the KDC")
}

// pkError acts on a KDC error to a PKINIT exchange: the KDC's offer (and
// its freshness token) to our first request; a group refused, for the
// first of those the KDC lists that is no weaker; a stale or missing
// token, for a new one. True when the next request is to be made.
func (x *asExchange) pkError(e messages.KRBError, hints types.PADataSequence) (bool, error) {
	token := func() ([]byte, bool) {
		for _, pa := range hints {
			if pa.PADataType == patype.PA_AS_FRESHNESS && len(pa.PADataValue) > 0 {
				return pa.PADataValue, true
			}
		}

		return nil, false
	}

	switch {
	case e.ErrorCode == errorcode.KDC_ERR_PREAUTH_REQUIRED && !x.pkNext:
		if !hints.Contains(patype.PA_PK_AS_REQ) {
			return false, krberror.Errorf(e, krberror.KDCError, "AS Exchange Error: the KDC does not offer PKINIT")
		}

		x.pkFresh, _ = token()
		x.pkNext = true

		return true, nil
	case e.ErrorCode == errorcode.KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED && x.pkNext && !x.pkGroupRetry:
		td, ok := pkinit.TDDHParameters(e.EData)
		if !ok {
			return false, krberror.Errorf(e, krberror.KDCError, "AS Exchange Error: the KDC refuses our DH group and lists none")
		}

		g := pkinit.PickGroup(td, x.pkMin)
		if g == 0 {
			return false, krberror.Errorf(e, krberror.KDCError, "AS Exchange Error: the KDC takes no DH group we take")
		}

		x.pkGroup, x.pkGroupRetry = g, true

		return true, nil
	case (e.ErrorCode == errorcode.KDC_ERR_PREAUTH_EXPIRED || e.ErrorCode == errorcode.KDC_ERR_PREAUTH_FAILED) && x.pkNext && !x.pkFreshRetry:
		if t, ok := token(); ok && !bytes.Equal(t, x.pkFresh) {
			x.pkFresh, x.pkFreshRetry = t, true

			return true, nil
		}
	}

	return false, nil
}

// reply checks the KDC's AS_REP to the request sent.
func (x *asExchange) reply(req messages.ASReq, sent, rb []byte, st *messages.FASTState) (messages.ASRep, error) {
	cl := x.cl

	var rep messages.ASRep
	if err := rep.Unmarshal(rb); err != nil {
		return rep, krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed to process the AS_REP")
	}

	// Only a type we asked for (as MIT checks): a KDC, or someone in the
	// middle, cannot push us onto a weaker one.
	if !slices.Contains(req.ReqBody.EType, rep.EncPart.EType) {
		return rep, krberror.NewErrorf(krberror.KRBMsgError, "AS Exchange Error: the AS_REP is encrypted in a type not asked for (%d)", rep.EncPart.EType)
	}

	var fr messages.KrbFastResponse

	if st != nil {
		// Armored: the FAST response checked, and its padata and names
		// (the finished part's) are the reply's.
		var err error
		if fr, err = st.Reply(rep.PAData, rep.Ticket, req.ReqBody.Nonce); err != nil {
			return rep, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: the armored AS_REP")
		}

		rep.PAData = fr.PAData
		rep.CName = fr.Finished.CName
		rep.CRealm = fr.Finished.CRealm
	}

	// The reply key: after SPAKE, K'[0], of the initial key's type; else
	// the pre-authentication key if the reply uses its type, else one by
	// the reply's salt.
	key := x.key
	crealm := x.realm

	if x.cl.anonymous {
		crealm = AnonymousRealm
	}

	switch {
	case x.pk:
		k, err := x.pkReplyKey(req, sent, rep)
		if err != nil {
			return rep, err
		}

		key = k
	case x.spakeNext == spakeSendResponse:
		if rep.EncPart.EType != x.key.KeyType {
			return rep, krberror.NewErrorf(krberror.KRBMsgError, "AS Exchange Error: the AS_REP after SPAKE is not in the initial key's type")
		}

		key = x.spakeKey
	case !x.haveKey || key.KeyType != rep.EncPart.EType:
		k, _, err := cl.keyFor(rep.EncPart.EType, req.ReqBody.CName, x.realm, rep.PAData)
		if err != nil {
			return rep, krberror.Errorf(err, krberror.DecryptingError, "AS Exchange Error: no key for the AS_REP")
		}

		key = k
	}

	// The KDC's answer to our encrypted challenge proves it knows our key
	// (RFC 6113 5.4.6).
	if st != nil && x.challenge && x.haveKey && x.spakeNext == spakeNone {
		if err := st.CheckKDCChallenge(x.key, rep.PAData); err != nil {
			return rep, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: the KDC's encrypted challenge")
		}
	}

	replyKey, err := fr.ReplyKey(key)
	if err != nil {
		return rep, krberror.Errorf(err, krberror.EncryptingError, "AS Exchange Error: the strengthened reply key")
	}

	if ok, err := rep.VerifyWithKeyRealm(cl.Config, req, sent, replyKey, cl.Now(), crealm); !ok {
		return rep, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: AS_REP is not valid or client password/keytab incorrect")
	}

	if x.pk {
		if err := x.pkCheckReply(rep, key); err != nil {
			return rep, err
		}
	}

	if !slices.Contains(req.ReqBody.EType, rep.DecryptedEncPart.Key.KeyType) {
		return rep, krberror.NewErrorf(krberror.KRBMsgError, "AS Exchange Error: a session key of a type not asked for (%d)", rep.DecryptedEncPart.Key.KeyType)
	}

	if rep.DecryptedEncPart.EncPAData.Contains(patype.PA_FX_FAST) || st != nil {
		cl.setFASTAvailable(x.realm)
	}

	if cl.Config.LibDefaults.KDCTimeSync == 1 {
		cl.syncTime(rep.DecryptedEncPart.AuthTime, 0)
	}

	return rep, nil
}

// pkReplyKey is PKINIT's reply key, from the reply's PA-PK-AS-REP.
func (x *asExchange) pkReplyKey(req messages.ASReq, sent []byte, rep messages.ASRep) (types.EncryptionKey, error) {
	if !x.pkNext || x.pkReq == nil {
		return types.EncryptionKey{}, krberror.NewErrorf(krberror.KRBMsgError, "AS Exchange Error: a reply to a request without PKINIT")
	}

	var v []byte

	for _, pa := range rep.PAData {
		if pa.PADataType == patype.PA_PK_AS_REP {
			v = pa.PADataValue
		}
	}

	if v == nil {
		return types.EncryptionKey{}, krberror.NewErrorf(krberror.KRBMsgError, "AS Exchange Error: no PA-PK-AS-REP in the reply")
	}

	trust, err := pkinit.TrustFromConfig(x.cl.Config, x.realm)
	if err != nil {
		return types.EncryptionKey{}, krberror.Errorf(err, krberror.ConfigError, "AS Exchange Error: PKINIT trust")
	}

	// Anonymous, the client's realm in the KDF is the anonymous one (MIT's
	// KDC renames the request's client so).
	crealm := x.realm
	if x.cl.anonymous {
		crealm = AnonymousRealm
	}

	k, err := x.pkReq.ReplyKey(v, trust, rep.EncPart.EType, req.ReqBody.CName, crealm, req.ReqBody.SName, x.realm, sent, x.cl.Now())
	if err != nil {
		return k, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: PKINIT reply")
	}

	return k, nil
}

// pkCheckReply checks what PKINIT asks of a decrypted reply: the KDC's
// contribution to the session key (PA-PKINIT-KX, RFC 8062 7), required
// when anonymous and checked whenever sent; anonymous, the ticket flagged
// so.
func (x *asExchange) pkCheckReply(rep messages.ASRep, replyKey types.EncryptionKey) error {
	var kx []byte

	for _, pa := range rep.PAData {
		if pa.PADataType == patype.PA_PKINIT_KX {
			kx = pa.PADataValue
		}
	}

	if kx == nil && x.cl.anonymous {
		return krberror.NewErrorf(krberror.KRBMsgError, "AS Exchange Error: an anonymous reply without PA-PKINIT-KX")
	}

	if kx != nil {
		if err := pkinit.CheckKX(kx, replyKey, rep.DecryptedEncPart.Key); err != nil {
			return krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: PA-PKINIT-KX")
		}
	}

	if x.cl.anonymous && !types.IsFlagSet(&rep.DecryptedEncPart.Flags, flags.Anonymous) {
		return krberror.NewErrorf(krberror.KRBMsgError, "AS Exchange Error: an anonymous ticket not flagged anonymous")
	}

	return nil
}

// disableEncryptedTimestamp is MIT's disable_encrypted_timestamp for the
// realm ([realms]).
func (cl *Client) disableEncryptedTimestamp(realm string) bool {
	for _, r := range cl.Config.Realms {
		if r.Realm == realm {
			return r.DisableEncryptedTimestamp
		}
	}

	return false
}

// preAuthHints is the padata of the KDC's last PREAUTH_REQUIRED, if any.
func (s *Settings) preAuthHints() types.PADataSequence {
	var pas types.PADataSequence

	if s.preAuthError != nil {
		_ = pas.Unmarshal(s.preAuthError.EData)
	}

	return pas
}

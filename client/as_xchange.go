package client

import (
	"errors"
	"slices"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/krberror"
	"github.com/go-krb5/krb5/messages"
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
	if cl.settings.assumePreAuthentication && armor == nil {
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
func (x *asExchange) padata(st *messages.FASTState) (types.PADataSequence, error) {
	pas := append(types.PADataSequence{}, x.base...)
	now := x.cl.Now()

	if x.haveKey {
		if st != nil && x.challenge {
			v, err := st.EncryptedChallenge(x.key, now)
			if err != nil {
				return nil, err
			}

			pas = append(pas, types.PAData{PADataType: patype.PA_ENCRYPTED_CHALLENGE, PADataValue: v})
		} else {
			ts, err := types.GetPAEncTSEncAsnMarshalledAt(now)
			if err != nil {
				return nil, err
			}

			ed, err := crypto.GetEncryptedData(ts, x.key, keyusage.AS_REQ_PA_ENC_TIMESTAMP, x.kvno)
			if err != nil {
				return nil, err
			}

			b, err := ed.Marshal()
			if err != nil {
				return nil, err
			}

			pas = append(pas, types.PAData{PADataType: patype.PA_ENC_TIMESTAMP, PADataValue: b})
		}
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

		pas, err := x.padata(st)
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

		switch {
		case e.ErrorCode == errorcode.KDC_ERR_PREAUTH_REQUIRED && (!x.haveKey || x.storedKey && !retriedStale):
			if x.storedKey {
				retriedStale = true
			}

			x.storedKey = false

			if err := x.keyFromHints(hints); err != nil {
				return messages.ASRep{}, krberror.Errorf(err, krberror.EncryptingError, "AS Exchange Error: failed setting AS_REQ PAData for pre-authentication required")
			}

			x.challenge = st != nil && hints.Contains(patype.PA_ENCRYPTED_CHALLENGE)

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

	// The reply key: the pre-authentication key if the reply uses its type,
	// else one by the reply's salt.
	key := x.key
	if !x.haveKey || key.KeyType != rep.EncPart.EType {
		k, _, err := cl.keyFor(rep.EncPart.EType, req.ReqBody.CName, x.realm, rep.PAData)
		if err != nil {
			return rep, krberror.Errorf(err, krberror.DecryptingError, "AS Exchange Error: no key for the AS_REP")
		}

		key = k
	}

	// The KDC's answer to our encrypted challenge proves it knows our key
	// (RFC 6113 5.4.6).
	if st != nil && x.challenge && x.haveKey {
		if err := st.CheckKDCChallenge(x.key, rep.PAData); err != nil {
			return rep, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: the KDC's encrypted challenge")
		}
	}

	replyKey, err := fr.ReplyKey(key)
	if err != nil {
		return rep, krberror.Errorf(err, krberror.EncryptingError, "AS Exchange Error: the strengthened reply key")
	}

	if ok, err := rep.VerifyWithKey(cl.Config, req, sent, replyKey, cl.Now()); !ok {
		return rep, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: AS_REP is not valid or client password/keytab incorrect")
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

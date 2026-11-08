package client

import (
	"github.com/SorinS/krb5/iana/errorcode"
	"github.com/SorinS/krb5/iana/flags"
	"github.com/SorinS/krb5/iana/keyusage"
	"github.com/SorinS/krb5/iana/msgtype"
	"github.com/SorinS/krb5/iana/nametype"
	"github.com/SorinS/krb5/iana/patype"
	"github.com/SorinS/krb5/krberror"
	"github.com/SorinS/krb5/messages"
	"github.com/SorinS/krb5/types"
)

// TGSREQGenerateAndExchange generates the TGS_REQ and performs a TGS exchange to retrieve a ticket to the specified SPN.
func (cl *Client) TGSREQGenerateAndExchange(spn types.PrincipalName, kdcRealm string, tgt messages.Ticket, sessionKey types.EncryptionKey, renewal bool) (tgsReq messages.TGSReq, tgsRep messages.TGSRep, err error) {
	tgsReq, err = messages.NewTGSReqAt(cl.Credentials.CName(), cl.Credentials.Domain(), kdcRealm, cl.Config, tgt, sessionKey, spn, renewal, cl.Now())
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.KRBMsgError, "TGS Exchange Error: failed to generate a new TGS_REQ")
	}

	return cl.TGSExchange(tgsReq, kdcRealm, tgt, sessionKey, 0)
}

// newTGSReqLike makes a TGS_REQ for what tgsReq asks, with the TGT given
// (a referral's, say) and the client's time now: user-to-user when tgsReq
// is.
func (cl *Client) newTGSReqLike(tgsReq messages.TGSReq, kdcRealm string, tgt messages.Ticket, sessionKey types.EncryptionKey) (messages.TGSReq, error) {
	// S4U: the same request, signed again.
	if tgsReq.S4UUser != nil || tgsReq.IsS4U2Proxy() {
		tgsReq.ReqBody.Realm = kdcRealm

		// Back in the client's realm, a cross-realm S4U2Self asks for the
		// client by its own name again, not the enterprise name its user's
		// realm needed (as Windows and MIT do).
		if tgsReq.S4UUser != nil && kdcRealm == cl.Credentials.Domain() &&
			tgsReq.ReqBody.SName.NameType == nametype.KRB_NT_ENTERPRISE {
			tgsReq.ReqBody.SName = cl.Credentials.CName()
		}

		err := tgsReq.SetPAData(cl.Credentials.Domain(), tgt, sessionKey, cl.Now())

		return tgsReq, err
	}

	if types.IsFlagSet(&tgsReq.ReqBody.KDCOptions, flags.EncTktInSkey) && len(tgsReq.ReqBody.AdditionalTickets) > 0 {
		return messages.NewUser2UserTGSReqAt(cl.Credentials.CName(), kdcRealm, cl.Config, tgt, sessionKey, tgsReq.ReqBody.SName,
			tgsReq.Renewal, tgsReq.ReqBody.AdditionalTickets[0], cl.Now())
	}

	return messages.NewTGSReqAt(cl.Credentials.CName(), cl.Credentials.Domain(), kdcRealm, cl.Config, tgt, sessionKey,
		tgsReq.ReqBody.SName, tgsReq.Renewal, cl.Now())
}

// TGSExchange exchanges the provided TGS_REQ with the KDC to retrieve a TGS_REP.
// Referrals are automatically handled.
// The client's cache is updated with the ticket received.
// With kdc_timesync (MIT's default), a KRB_AP_ERR_SKEW error from the KDC
// sets the client's clock offset from the error's time, and the request is
// made again once, as MIT does. tgt is the ticket the request is made with.
func (cl *Client) TGSExchange(tgsReq messages.TGSReq, kdcRealm string, tgt messages.Ticket, sessionKey types.EncryptionKey, referral int) (messages.TGSReq, messages.TGSRep, error) {
	var (
		tgsRep    messages.TGSRep
		r         []byte
		skewFixed bool
	)

	var st *messages.FASTState

	for {
		var (
			b   []byte
			err error
		)

		st, b, err = cl.tgsRequest(tgsReq, kdcRealm, sessionKey)
		if err != nil {
			return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: failed to marshal TGS_REQ")
		}

		r, err = cl.sendToKDC(b, kdcRealm)
		if err == nil {
			break
		}

		e, ok := err.(messages.KRBError)
		if !ok {
			return tgsReq, tgsRep, krberror.Errorf(err, krberror.NetworkingError, "TGS Exchange Error: issue sending TGS_REQ to KDC")
		}

		// Armored, the KDC's error is inside the armor (when it could
		// read the armor).
		if st != nil {
			if inner, _, ferr := st.Error(e, tgsReq.ReqBody.Nonce); ferr == nil {
				e = inner
				err = inner
			}
		}

		if e.ErrorCode == errorcode.KRB_AP_ERR_SKEW && !skewFixed && cl.Config.LibDefaults.KDCTimeSync == 1 {
			cl.syncTime(e.STime, e.Susec)
			skewFixed = true

			if tgsReq, err = cl.newTGSReqLike(tgsReq, kdcRealm, tgt, sessionKey); err != nil {
				return tgsReq, tgsRep, krberror.Errorf(err, krberror.KRBMsgError, "TGS Exchange Error: failed to generate a new TGS_REQ")
			}

			continue
		}

		return tgsReq, tgsRep, krberror.Errorf(err, krberror.KDCError, "TGS Exchange Error: kerberos error response from KDC when requesting for %s", tgsReq.ReqBody.SName.PrincipalNameString())
	}

	err := tgsRep.Unmarshal(r)
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: failed to process the TGS_REP")
	}

	// The reply is encrypted in the authenticator's subkey (usage 9), or
	// in the session key (usage 8) by a request without one; armored, the
	// key is strengthened. An unarmored reply to an armored request is
	// taken (as MIT does): the subkey protects it all the same.
	replyKey, usage := sessionKey, uint32(keyusage.TGS_REP_ENCPART_SESSION_KEY)
	if len(tgsReq.SubKey.KeyValue) > 0 {
		replyKey, usage = tgsReq.SubKey, keyusage.TGS_REP_ENCPART_AUTHENTICATOR_SUB_KEY
	}

	repPAData := types.PADataSequence(tgsRep.PAData)
	if st != nil && repPAData.Contains(patype.PA_FX_FAST) {
		fr, err := st.Reply(tgsRep.PAData, tgsRep.Ticket, tgsReq.ReqBody.Nonce)
		if err != nil {
			return tgsReq, tgsRep, krberror.Errorf(err, krberror.KRBMsgError, "TGS Exchange Error: the armored TGS_REP")
		}

		if replyKey, err = fr.ReplyKey(replyKey); err != nil {
			return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncryptingError, "TGS Exchange Error: the strengthened reply key")
		}

		tgsRep.PAData = fr.PAData
		tgsRep.CName = fr.Finished.CName
		tgsRep.CRealm = fr.Finished.CRealm
	}

	err = tgsRep.DecryptEncPartUsage(replyKey, usage)
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: failed to process the TGS_REP")
	}

	if ok, err := tgsRep.VerifyAt(cl.Config, tgsReq, cl.Now()); !ok {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: TGS_REP is not valid")
	}

	referred := len(tgsRep.Ticket.SName.NameString) > 0 && tgsRep.Ticket.SName.NameString[0] == "krbtgt" &&
		!tgsRep.Ticket.SName.Equal(tgsReq.ReqBody.SName)

	// A referral on the way to an S4U2Self ticket is the client's, with the
	// user's PAC: only the final reply names the user.
	if !referred {
		if err := tgsRep.VerifyS4U(tgsReq); err != nil {
			return tgsReq, tgsRep, krberror.Errorf(err, krberror.KRBMsgError, "TGS Exchange Error: S4U")
		}
	}

	if referred {
		if referral > 5 {
			return tgsReq, tgsRep, krberror.Errorf(err, krberror.KRBMsgError, "TGS Exchange Error: maximum number of referrals exceeded")
		}
		// Server referral https://tools.ietf.org/html/rfc6806.html#section-8
		// The TGS Rep contains a TGT for another domain as the service resides in that domain.
		// An S4U referral is not the client's own TGT (a cross-realm S4U2Self's
		// carries the user's PAC, back to the client's realm): it must not
		// replace the client's session for that realm.
		if tgsReq.S4UUser == nil && !tgsReq.IsS4U2Proxy() {
			cl.addSession(tgsRep.Ticket, tgsRep.DecryptedEncPart)
		}
		realm := tgsRep.Ticket.SName.NameString[len(tgsRep.Ticket.SName.NameString)-1]
		referral++

		// The same request (user-to-user too) to the referred realm, with its TGT.
		tgsReq, err = cl.newTGSReqLike(tgsReq, realm, tgsRep.Ticket, tgsRep.DecryptedEncPart.Key)
		if err != nil {
			return tgsReq, tgsRep, err
		}

		return cl.TGSExchange(tgsReq, realm, tgsRep.Ticket, tgsRep.DecryptedEncPart.Key, referral)
	}

	// A ticket in a user's name is not the client's own: it does not go in
	// the cache GetServiceTicket answers from.
	if tgsReq.S4UUser != nil || tgsReq.IsS4U2Proxy() {
		return tgsReq, tgsRep, nil
	}

	cl.cache.addEntry(
		tgsRep.Ticket,
		tgsRep.DecryptedEncPart.AuthTime,
		tgsRep.DecryptedEncPart.StartTime,
		tgsRep.DecryptedEncPart.EndTime,
		tgsRep.DecryptedEncPart.RenewTill,
		tgsRep.DecryptedEncPart.Flags,
		tgsRep.DecryptedEncPart.Key,
	)
	cl.Log("ticket added to cache for %s (EndTime: %v)", tgsRep.Ticket.SName.PrincipalNameString(), tgsRep.DecryptedEncPart.EndTime)

	return tgsReq, tgsRep, err
}

// tgsRequest is the TGS_REQ to send: armored (RFC 6113) when the KDC said
// it does FAST, implicitly by the TGT the request is made with, or with
// the device armor as well (FASTDeviceArmor); as it is otherwise. The
// FAST state is nil for an unarmored request.
func (cl *Client) tgsRequest(tgsReq messages.TGSReq, kdcRealm string, sessionKey types.EncryptionKey) (*messages.FASTState, []byte, error) {
	device := cl.settings.deviceArmor
	if device != nil && device.Ticket.Realm != kdcRealm {
		device = nil
	}

	if len(tgsReq.SubKey.KeyValue) == 0 || cl.settings.DisablePAFXFAST() || (device == nil && !cl.fastAvailable(kdcRealm)) {
		b, err := tgsReq.Marshal()
		return nil, b, err
	}

	var (
		inner, outer types.PADataSequence
		apReq        []byte
	)

	for _, pa := range tgsReq.PAData {
		if pa.PADataType == patype.PA_TGS_REQ {
			outer = append(outer, pa)
			apReq = pa.PADataValue
		} else {
			inner = append(inner, pa)
		}
	}

	var (
		st  messages.FASTState
		err error
	)

	if device != nil {
		st, err = messages.NewFASTArmorTGSExplicit(*device, tgsReq.SubKey, cl.Now())
	} else {
		st, err = messages.NewFASTArmorTGS(tgsReq.SubKey, sessionKey)
	}

	if err != nil {
		return nil, nil, err
	}

	b, err := st.Wrap(msgtype.KRB_TGS_REQ, inner, outer, tgsReq.ReqBody, apReq)

	return &st, b, err
}

// GetServiceTicket makes a request to get a service ticket for the SPN specified
// SPN format: <SERVICE>/<FQDN> Eg. HTTP/www.example.com
// The ticket will be added to the client's ticket cache.
func (cl *Client) GetServiceTicket(spn string) (messages.Ticket, types.EncryptionKey, error) {
	var (
		tkt  messages.Ticket
		skey types.EncryptionKey
	)

	if cl.Config == nil {
		return tkt, skey, krberror.New(krberror.ConfigError, "client has no krb5 configuration")
	}

	if tkt, skey, ok := cl.GetCachedTicket(spn); ok {
		// Already a valid ticket in the cache.
		return tkt, skey, nil
	}

	princ := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, spn)
	realm := cl.spnRealm(princ)

	// if we don't know the SPN's realm, ask the client realm's KDC.
	if realm == "" {
		realm = cl.Credentials.Realm()
	}

	tgt, skey, err := cl.sessionTGT(realm)
	if err != nil {
		return tkt, skey, err
	}

	_, tgsRep, err := cl.TGSREQGenerateAndExchange(princ, realm, tgt, skey, false)
	if err != nil {
		return tkt, skey, err
	}

	return tgsRep.Ticket, tgsRep.DecryptedEncPart.Key, nil
}

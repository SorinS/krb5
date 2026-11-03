package client

import (
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/crypto/etype"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/keyusage"
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
func (cl *Client) ASExchange(realm string, ASReq messages.ASReq, referral int) (messages.ASRep, error) {
	if ok, err := cl.IsConfigured(); !ok {
		return messages.ASRep{}, krberror.Errorf(err, krberror.ConfigError, "AS Exchange cannot be performed")
	}

	// Set PAData if required.
	err := setPAData(cl, cl.settings.preAuthError, &ASReq)
	if err != nil {
		return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: issue with setting PAData on AS_REQ")
	}

	var (
		rb          []byte
		preAuthDone bool
		skewFixed   bool
	)

	for {
		b, err := ASReq.Marshal()
		if err != nil {
			return messages.ASRep{}, krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed marshaling AS_REQ")
		}

		rb, err = cl.sendToKDC(b, realm)
		if err == nil {
			break
		}

		e, ok := err.(messages.KRBError)
		if !ok {
			return messages.ASRep{}, krberror.Errorf(err, krberror.NetworkingError, "AS Exchange Error: failed sending AS_REQ to KDC")
		}

		switch {
		case (e.ErrorCode == errorcode.KDC_ERR_PREAUTH_REQUIRED || e.ErrorCode == errorcode.KDC_ERR_PREAUTH_FAILED) && !preAuthDone:
			// From now on assume this client will need to do this pre-auth and set the PAData.
			cl.settings.assumePreAuthentication = true
			preAuthDone = true

			if e.ErrorCode == errorcode.KDC_ERR_PREAUTH_REQUIRED {
				// Its ETYPE-INFO2 (the salt) serves later logins too.
				pe := e
				cl.settings.preAuthError = &pe
			}

			perr := cl.settings.preAuthError
			if perr == nil {
				perr = &e
			}

			err = setPAData(cl, perr, &ASReq)
			if err != nil {
				return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: failed setting AS_REQ PAData for pre-authentication required")
			}
		case e.ErrorCode == errorcode.KRB_AP_ERR_SKEW && !skewFixed && cl.Config.LibDefaults.KDCTimeSync == 1:
			cl.syncTime(e.STime, e.Susec)
			skewFixed = true

			// The timestamp again, by the corrected clock.
			err = setPAData(cl, cl.settings.preAuthError, &ASReq)
			if err != nil {
				return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: failed setting AS_REQ PAData after the clock was corrected")
			}
		case e.ErrorCode == errorcode.KDC_ERR_WRONG_REALM:
			// Client referral https://tools.ietf.org/html/rfc6806.html#section-7
			if referral > 5 {
				return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "maximum number of client referrals exceeded")
			}

			referral++

			return cl.ASExchange(e.CRealm, ASReq, referral)
		default:
			return messages.ASRep{}, krberror.Errorf(err, krberror.KDCError, "AS Exchange Error: kerberos error response from KDC")
		}
	}

	var ASRep messages.ASRep

	err = ASRep.Unmarshal(rb)
	if err != nil {
		return messages.ASRep{}, krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed to process the AS_REP")
	}

	if ok, err := ASRep.VerifyAt(cl.Config, cl.Credentials, ASReq, cl.Now()); !ok {
		return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: AS_REP is not valid or client password/keytab incorrect")
	}

	if cl.Config.LibDefaults.KDCTimeSync == 1 {
		cl.syncTime(ASRep.DecryptedEncPart.AuthTime, 0)
	}

	return ASRep, nil
}

// setPAData adds pre-authentication data to the AS_REQ.
func setPAData(cl *Client, krberr *messages.KRBError, req *messages.ASReq) error {
	if !cl.settings.DisablePAFXFAST() && !req.PAData.Contains(patype.PA_REQ_ENC_PA_REP) {
		pa := types.PAData{PADataType: patype.PA_REQ_ENC_PA_REP}
		req.PAData = append(req.PAData, pa)
	}

	if cl.settings.AssumePreAuthentication() {
		var (
			et   etype.EType
			err  error
			key  types.EncryptionKey
			kvno int
		)

		if krberr == nil {
			etn := cl.settings.preAuthEType
			if etn == 0 {
				etn = int32(cl.Config.LibDefaults.PreferredPreauthTypes[0])
			}

			et, err = crypto.GetEtype(etn)
			if err != nil {
				return krberror.Errorf(err, krberror.EncryptingError, "error getting etype for pre-auth encryption")
			}

			key, kvno, err = cl.Key(et, 0, nil)
			if err != nil {
				return krberror.Errorf(err, krberror.EncryptingError, "error getting key from credentials")
			}
		} else {
			et, err = preAuthEType(krberr)
			if err != nil {
				return krberror.Errorf(err, krberror.EncryptingError, "error getting etype for pre-auth encryption")
			}

			cl.settings.preAuthEType = et.GetETypeID()

			key, kvno, err = cl.Key(et, 0, krberr)
			if err != nil {
				return krberror.Errorf(err, krberror.EncryptingError, "error getting key from credentials")
			}
		}

		paTSb, err := types.GetPAEncTSEncAsnMarshalledAt(cl.Now())
		if err != nil {
			return krberror.Errorf(err, krberror.KRBMsgError, "error creating PAEncTSEnc for Pre-Authentication")
		}

		paEncTS, err := crypto.GetEncryptedData(paTSb, key, keyusage.AS_REQ_PA_ENC_TIMESTAMP, kvno)
		if err != nil {
			return krberror.Errorf(err, krberror.EncryptingError, "error encrypting pre-authentication timestamp")
		}

		pb, err := paEncTS.Marshal()
		if err != nil {
			return krberror.Errorf(err, krberror.EncodingError, "error marshaling the PAEncTSEnc encrypted data")
		}

		pa := types.PAData{
			PADataType:  patype.PA_ENC_TIMESTAMP,
			PADataValue: pb,
		}

		for i, pa := range req.PAData {
			if pa.PADataType == patype.PA_ENC_TIMESTAMP {
				req.PAData[i] = req.PAData[len(req.PAData)-1]
				req.PAData = req.PAData[:len(req.PAData)-1]
			}
		}

		req.PAData = append(req.PAData, pa)
	}

	return nil
}

// preAuthEType establishes what encryption type to use for pre-authentication from the KRBError returned from the KDC.
func preAuthEType(krberr *messages.KRBError) (etype etype.EType, err error) {
	// RFC 4120 5.2.7.5 covers the preference order of ETYPE-INFO2 and ETYPE-INFO.
	var (
		etypeID int32
		pas     types.PADataSequence
	)

	e := pas.Unmarshal(krberr.EData)
	if e != nil {
		err = krberror.Errorf(e, krberror.EncodingError, "error unmashalling KRBError data")
		return
	}

Loop:
	for _, pa := range pas {
		switch pa.PADataType {
		case patype.PA_ETYPE_INFO2:
			info, e := pa.GetETypeInfo2()
			if e != nil {
				err = krberror.Errorf(e, krberror.EncodingError, "error unmashalling ETYPE-INFO2 data")
				return
			}

			etypeID = info[0].EType

			break Loop
		case patype.PA_ETYPE_INFO:
			info, e := pa.GetETypeInfo()
			if e != nil {
				err = krberror.Errorf(e, krberror.EncodingError, "error unmashalling ETYPE-INFO data")
				return
			}

			etypeID = info[0].EType
		}
	}

	etype, e = crypto.GetEtype(etypeID)
	if e != nil {
		err = krberror.Errorf(e, krberror.EncryptingError, "error creating etype")
		return
	}

	return etype, nil
}

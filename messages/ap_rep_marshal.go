package messages

import (
	"time"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/asn1tools"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana"
	"github.com/go-krb5/krb5/iana/asn1apptag"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/msgtype"
	"github.com/go-krb5/krb5/krberror"
	"github.com/go-krb5/krb5/types"
)

// encAPRepPartNoSubkey is EncAPRepPart without the optional subkey, which
// the asn1 package would otherwise encode, empty, as present.
type encAPRepPartNoSubkey struct {
	CTime          time.Time `asn1:"generalized,explicit,tag:0"`
	Cusec          int       `asn1:"explicit,tag:1"`
	SequenceNumber int64     `asn1:"explicit,tag:3"`
}

// Marshal the EncAPRepPart (with its application tag). The subkey is left
// out when it has no key value; the sequence number is always in.
func (a *EncAPRepPart) Marshal() ([]byte, error) {
	var (
		b   []byte
		err error
	)

	if len(a.Subkey.KeyValue) == 0 {
		b, err = asn1.Marshal(encAPRepPartNoSubkey{CTime: a.CTime, Cusec: a.Cusec, SequenceNumber: a.SequenceNumber})
	} else {
		b, err = asn1.Marshal(*a)
	}

	if err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "error marshaling EncAPRepPart")
	}

	return asn1tools.AddASNAppTag(b, asn1apptag.EncAPRepPart), nil
}

// NewAPRep makes the AP-REP to an AP-REQ (RFC 4120 3.2.4): the time of
// the client's authenticator, and the subkey (optional) and sequence
// number of the server, encrypted in the ticket's session key (key usage
// 12).
func NewAPRep(sessionKey types.EncryptionKey, ctime time.Time, cusec int, subkey types.EncryptionKey, seq int64) (APRep, error) {
	part := EncAPRepPart{CTime: ctime.UTC().Truncate(time.Second), Cusec: cusec, Subkey: subkey, SequenceNumber: seq}

	b, err := part.Marshal()
	if err != nil {
		return APRep{}, err
	}

	ed, err := crypto.GetEncryptedData(b, sessionKey, keyusage.AP_REP_ENCPART, 0)
	if err != nil {
		return APRep{}, krberror.Errorf(err, krberror.EncryptingError, "error encrypting EncAPRepPart")
	}

	return APRep{PVNO: iana.PVNO, MsgType: msgtype.KRB_AP_REP, EncPart: ed}, nil
}

// Marshal the APRep (with its application tag).
func (a *APRep) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(*a)
	if err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "error marshaling AP_REP")
	}

	return asn1tools.AddASNAppTag(b, asn1apptag.APREP), nil
}

// Decrypt the AP-REP's encrypted part with the session key and check it is
// the reply to the authenticator of time ctime and cusec (RFC 4120 3.2.5).
func (a *APRep) Decrypt(sessionKey types.EncryptionKey, ctime time.Time, cusec int) (EncAPRepPart, error) {
	var p EncAPRepPart

	b, err := crypto.DecryptEncPart(a.EncPart, sessionKey, keyusage.AP_REP_ENCPART)
	if err != nil {
		return p, krberror.Errorf(err, krberror.DecryptingError, "error decrypting AP_REP")
	}

	if err = p.Unmarshal(b); err != nil {
		return p, err
	}

	if p.CTime.Unix() != ctime.Unix() || p.Cusec != cusec {
		return p, krberror.NewErrorf(krberror.KRBMsgError, "AP_REP's time %v.%06d is not the authenticator's %v.%06d",
			p.CTime.UTC(), p.Cusec, ctime.UTC(), cusec)
	}

	return p, nil
}

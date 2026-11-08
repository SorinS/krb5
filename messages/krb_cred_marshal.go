package messages

import (
	"github.com/go-krb5/x/encoding/asn1"

	"github.com/SorinS/krb5/asn1tools"
	"github.com/SorinS/krb5/crypto"
	"github.com/SorinS/krb5/iana"
	"github.com/SorinS/krb5/iana/asn1apptag"
	"github.com/SorinS/krb5/iana/keyusage"
	"github.com/SorinS/krb5/iana/msgtype"
	"github.com/SorinS/krb5/krberror"
	"github.com/SorinS/krb5/types"
)

// encKrbCredPartInfos is EncKrbCredPart with only its ticket info, which is
// all that forwarding sends (the optional nonce, times and addresses
// would otherwise be encoded, empty, as present).
type encKrbCredPartInfos struct {
	TicketInfo []KrbCredInfo `asn1:"explicit,tag:0"`
}

// Marshal the EncKrbCredPart (with its application tag): its ticket info
// only (no nonce, timestamp or addresses, which MIT's forwarding leaves
// out too).
func (k *EncKrbCredPart) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(encKrbCredPartInfos{TicketInfo: k.TicketInfo}, asn1.WithMarshalSlicePreserveTypes(true),
		asn1.WithMarshalSliceAllowStrings(true))
	if err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "error marshaling EncKrbCredPart")
	}

	return asn1tools.AddASNAppTag(b, asn1apptag.EncKrbCredPart), nil
}

// NewKRBCred makes a KRB-CRED (RFC 4120 3.6) carrying the tickets, with
// their keys and details in infos (one each, in order), its part
// encrypted in key (usage 14): as a forwarded TGT is sent, for GSS-API
// delegation.
func NewKRBCred(tickets []Ticket, infos []KrbCredInfo, key types.EncryptionKey) (KRBCred, error) {
	k := KRBCred{PVNO: iana.PVNO, MsgType: msgtype.KRB_CRED, Tickets: tickets,
		DecryptedEncPart: EncKrbCredPart{TicketInfo: infos}}

	b, err := k.DecryptedEncPart.Marshal()
	if err != nil {
		return k, err
	}

	k.EncPart, err = crypto.GetEncryptedData(b, key, keyusage.KRB_CRED_ENCPART, 0)
	if err != nil {
		return k, krberror.Errorf(err, krberror.EncryptingError, "error encrypting EncKrbCredPart")
	}

	return k, nil
}

// Marshal the KRBCred (with its application tag).
func (k *KRBCred) Marshal() ([]byte, error) {
	// tickets [2] SEQUENCE OF Ticket.
	var seq []byte

	for _, t := range k.Tickets {
		b, err := t.Marshal()
		if err != nil {
			return nil, krberror.Errorf(err, krberror.EncodingError, "error marshaling the tickets of KRB_CRED")
		}

		seq = append(seq, b...)
	}

	// A RawValue is written as its own tag, whatever the field's says: the
	// [2] around the SEQUENCE is built here.
	seqDER, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: seq})
	if err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "error marshaling the tickets of KRB_CRED")
	}

	tkts := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, IsCompound: true, Bytes: seqDER}
	m := marshalKRBCred{PVNO: k.PVNO, MsgType: k.MsgType, Tickets: tkts, EncPart: k.EncPart}

	b, err := asn1.Marshal(m, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
	if err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "error marshaling KRB_CRED")
	}

	return asn1tools.AddASNAppTag(b, asn1apptag.KRBCred), nil
}

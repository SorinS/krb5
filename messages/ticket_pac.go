package messages

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/adtype"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/pac"
	"github.com/go-krb5/krb5/types"
)

// VerifyPACKDC checks the KDC's signatures in the ticket's PAC with the key
// of the KDC's krbtgt principal, as MIT's krb5_kdc_verify_ticket does: the
// KDC signature (over the server signature) always, and, unless the ticket
// is for a krbtgt or kadmin/changepw principal, the ticket checksum and the
// full checksum (MS-PAC 2.8.3 and 2.8.5) too, both of which Windows and MIT
// KDCs add since November 2022. The server signature is checked with
// serviceKey, which also decrypts the ticket. It returns the PAC, and
// false when the ticket has none.
func (t *Ticket) VerifyPACKDC(serviceKey, krbtgtKey types.EncryptionKey) (bool, pac.PACType, error) {
	var p pac.PACType

	plain, err := crypto.DecryptEncPart(t.EncPart, serviceKey, keyusage.KDC_REP_TICKET)
	if err != nil {
		return false, p, fmt.Errorf("error decrypting Ticket EncPart: %w", err)
	}

	var enc EncTicketPart
	if err = enc.Unmarshal(plain); err != nil {
		return false, p, fmt.Errorf("error unmarshalling encrypted part: %w", err)
	}

	recoded, pacData, found, err := ticketWithZeroPAC(plain)
	if err != nil {
		return false, p, err
	}

	if !found {
		return false, p, nil
	}

	if err = p.Unmarshal(pacData); err != nil {
		return true, p, fmt.Errorf("error unmarshalling PAC: %w", err)
	}

	if err = p.ProcessPACInfoBuffers(serviceKey, nil); err != nil {
		return true, p, err
	}

	if err = p.VerifyKDCSignature(krbtgtKey); err != nil {
		return true, p, err
	}

	if shouldHaveTicketSignature(t.SName) {
		if err = p.VerifyTicketChecksum(krbtgtKey, recoded); err != nil {
			return true, p, err
		}

		if err = p.VerifyFullChecksum(krbtgtKey); err != nil {
			return true, p, err
		}
	}

	if err = p.ValidateClientInfo(enc.CName, enc.CRealm, enc.AuthTime); err != nil {
		return true, p, err
	}

	return true, p, nil
}

// shouldHaveTicketSignature reports whether a ticket for the principal
// carries the ticket and full checksums: MS-PAC 2.8.3 leaves them out of
// tickets for krbtgt and kadmin/changepw.
func shouldHaveTicketSignature(sname types.PrincipalName) bool {
	if len(sname.NameString) > 0 && strings.EqualFold(sname.NameString[0], "krbtgt") {
		return false
	}

	return !(len(sname.NameString) == 2 && sname.NameString[0] == "kadmin" && sname.NameString[1] == "changepw")
}

// ticketWithZeroPAC re-encodes a ticket's EncTicketPart (DER) with the
// ad-data of the first PAC inside an AD-IF-RELEVANT element replaced by a
// single zero byte: what the ticket checksum signs (MIT's
// krb5_kdc_verify_ticket, MS-PAC 2.8.3). It returns the PAC too.
func ticketWithZeroPAC(encTicketPart []byte) ([]byte, []byte, bool, error) {
	var app asn1.RawValue

	if rest, err := asn1.Unmarshal(encTicketPart, &app); err != nil || len(rest) != 0 ||
		app.Class != asn1.ClassApplication {
		return nil, nil, false, errors.New("EncTicketPart is not an application-tagged value")
	}

	var seq asn1.RawValue
	if rest, err := asn1.Unmarshal(app.Bytes, &seq); err != nil || len(rest) != 0 || seq.Tag != asn1.TagSequence {
		return nil, nil, false, errors.New("EncTicketPart is not a SEQUENCE")
	}

	fields, err := derElements(seq.Bytes)
	if err != nil {
		return nil, nil, false, err
	}

	for fi, f := range fields {
		if f.Class != asn1.ClassContextSpecific || f.Tag != 10 {
			continue
		}

		var authz asn1.RawValue
		if _, err = asn1.Unmarshal(f.Bytes, &authz); err != nil {
			return nil, nil, false, err
		}

		entries, err := derElements(authz.Bytes)
		if err != nil {
			return nil, nil, false, err
		}

		for ei, e := range entries {
			var entry types.AuthorizationDataEntry
			if err = entry.Unmarshal(e.FullBytes); err != nil {
				return nil, nil, false, err
			}

			if entry.ADType != adtype.ADIfRelevant {
				continue
			}

			var inner types.AuthorizationData
			if err = inner.Unmarshal(entry.ADData); err != nil {
				return nil, nil, false, err
			}

			for ii := range inner {
				if inner[ii].ADType != adtype.ADWin2KPAC {
					continue
				}

				pacData := inner[ii].ADData

				recoded, err := replaceADData(e, entry.ADData, ii, []byte{0})
				if err != nil {
					return nil, nil, false, err
				}

				entries[ei] = recoded
				fields[fi] = derTagged(f, derTagged(authz, derConcat(entries)).FullBytes)

				return derTagged(app, derTagged(seq, derConcat(fields)).FullBytes).FullBytes, pacData, true, nil
			}
		}
	}

	return nil, nil, false, nil
}

// replaceADData re-encodes an AuthorizationData entry (an AD-IF-RELEVANT
// whose ad-data is the DER ifRelevant) with the ad-data of its index'th
// inner element set to data.
func replaceADData(entry asn1.RawValue, ifRelevant []byte, index int, data []byte) (asn1.RawValue, error) {
	var adSeq asn1.RawValue
	if _, err := asn1.Unmarshal(ifRelevant, &adSeq); err != nil {
		return entry, err
	}

	inner, err := derElements(adSeq.Bytes)
	if err != nil {
		return entry, err
	}

	elemFields, err := derElements(inner[index].Bytes)
	if err != nil {
		return entry, err
	}

	for i, ef := range elemFields {
		if ef.Class == asn1.ClassContextSpecific && ef.Tag == 1 {
			octets := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagOctetString}
			elemFields[i] = derTagged(ef, derTagged(octets, data).FullBytes)
		}
	}

	inner[index] = derTagged(inner[index], derConcat(elemFields))
	newIfRelevant := derTagged(adSeq, derConcat(inner)).FullBytes

	entryFields, err := derElements(entry.Bytes)
	if err != nil {
		return entry, err
	}

	for i, ef := range entryFields {
		if ef.Class == asn1.ClassContextSpecific && ef.Tag == 1 {
			octets := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagOctetString}
			entryFields[i] = derTagged(ef, derTagged(octets, newIfRelevant).FullBytes)
		}
	}

	return derTagged(entry, derConcat(entryFields)), nil
}

// derElements splits DER contents into its elements.
func derElements(b []byte) ([]asn1.RawValue, error) {
	var out []asn1.RawValue

	for len(b) > 0 {
		var v asn1.RawValue

		rest, err := asn1.Unmarshal(b, &v)
		if err != nil {
			return nil, err
		}

		out = append(out, v)
		b = rest
	}

	return out, nil
}

func derConcat(vs []asn1.RawValue) []byte {
	var b []byte
	for _, v := range vs {
		b = append(b, v.FullBytes...)
	}

	return b
}

// derTagged encodes contents under like's tag (class, tag, constructed).
func derTagged(like asn1.RawValue, contents []byte) asn1.RawValue {
	v := asn1.RawValue{Class: like.Class, Tag: like.Tag, IsCompound: like.IsCompound, Bytes: contents}

	first := byte(like.Class << 6)
	if like.IsCompound {
		first |= 0x20
	}

	var b []byte
	if like.Tag < 31 {
		b = append(b, first|byte(like.Tag))
	} else {
		b = append(b, first|0x1f)

		var t []byte
		for n := like.Tag; n > 0; n >>= 7 {
			t = append([]byte{byte(n & 0x7f)}, t...)
		}

		for i := 0; i < len(t)-1; i++ {
			t[i] |= 0x80
		}

		b = append(b, t...)
	}

	if n := len(contents); n < 0x80 {
		b = append(b, byte(n))
	} else {
		var l []byte
		for ; n > 0; n >>= 8 {
			l = append([]byte{byte(n)}, l...)
		}

		b = append(b, 0x80|byte(len(l)))
		b = append(b, l...)
	}

	v.FullBytes = append(b, contents...)

	return v
}

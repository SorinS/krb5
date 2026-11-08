package pkinit

import (
	"crypto"
	"crypto/sha1"
	"encoding/asn1"
	"encoding/binary"

	krbasn1 "github.com/go-krb5/x/encoding/asn1"

	kcrypto "github.com/SorinS/krb5/crypto"
	"github.com/SorinS/krb5/types"
)

// A KDF is one of RFC 8636's key derivation functions, by its hash; KDFOld
// is RFC 4556's octetstring2key, when the KDC names none.
type KDF crypto.Hash

// The KDFs.
const (
	KDFOld    KDF = 0
	KDFSHA1   KDF = KDF(crypto.SHA1)
	KDFSHA256 KDF = KDF(crypto.SHA256)
	KDFSHA384 KDF = KDF(crypto.SHA384)
	KDFSHA512 KDF = KDF(crypto.SHA512)
)

// DefaultKDFs are the KDFs offered, in preference order: SHA-256 first
// (RFC 8636 6 requires it), then SHA-512, SHA-384, SHA-1.
var DefaultKDFs = []KDF{KDFSHA256, KDFSHA512, KDFSHA384, KDFSHA1}

var (
	oidKDFSHA1   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 6, 1}
	oidKDFSHA256 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 6, 2}
	oidKDFSHA512 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 6, 3}
	oidKDFSHA384 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 6, 4}
)

func (k KDF) oid() asn1.ObjectIdentifier {
	switch k {
	case KDFSHA1:
		return oidKDFSHA1
	case KDFSHA512:
		return oidKDFSHA512
	case KDFSHA384:
		return oidKDFSHA384
	}

	return oidKDFSHA256
}

// kdfOf is the KDF an OID names; false for one we do not know.
func kdfOf(o asn1.ObjectIdentifier) (KDF, bool) {
	for _, k := range DefaultKDFs {
		if k.oid().Equal(o) {
			return k, true
		}
	}

	return 0, false
}

// OctetString2Key is RFC 4556 3.2.3.1's: random-to-key of the first
// seed-length bytes of SHA-1(0 || x) || SHA-1(1 || x) || ...
func OctetString2Key(etypeID int32, x []byte) (types.EncryptionKey, error) {
	e, err := kcrypto.GetEtype(etypeID)
	if err != nil {
		return types.EncryptionKey{}, err
	}

	n := e.GetKeySeedBitLength() / 8

	var out []byte

	for counter := byte(0); len(out) < n; counter++ {
		h := sha1.New()
		h.Write([]byte{counter})
		h.Write(x)
		out = h.Sum(out)
	}

	return kcrypto.RandomToKey(etypeID, out[:n])
}

// krbOpts are the Kerberos module's encoding options (GeneralString name
// components).
var krbOpts = []krbasn1.MarshalOpt{krbasn1.WithMarshalSlicePreserveTypes(true), krbasn1.WithMarshalSliceAllowStrings(true)}

// krb5PrincipalName is RFC 4556's KRB5PrincipalName.
type krb5PrincipalName struct {
	Realm         string              `asn1:"general,explicit,tag:0"`
	PrincipalName types.PrincipalName `asn1:"explicit,tag:1"`
}

type pkinitSuppPubInfo struct {
	EType   int32  `asn1:"explicit,tag:0"`
	ASReq   []byte `asn1:"explicit,tag:1"`
	PKASRep []byte `asn1:"explicit,tag:2"`
}

type otherInfo struct {
	AlgorithmID struct {
		Algorithm asn1.ObjectIdentifier
	}
	PartyUInfo  []byte `asn1:"explicit,tag:0"`
	PartyVInfo  []byte `asn1:"explicit,tag:1"`
	SuppPubInfo []byte `asn1:"explicit,tag:2"`
}

// OtherInfo is RFC 8636 6's OtherInfo for the KDF: the client's and the
// server's names, the reply's encryption type, the AS-REQ as sent and the
// PA-PK-AS-REP's value.
func OtherInfo(k KDF, client types.PrincipalName, crealm string, server types.PrincipalName, srealm string, etypeID int32, asReq, pkASRep []byte) ([]byte, error) {
	u, err := krbasn1.Marshal(krb5PrincipalName{Realm: crealm, PrincipalName: client}, krbOpts...)
	if err != nil {
		return nil, err
	}

	v, err := krbasn1.Marshal(krb5PrincipalName{Realm: srealm, PrincipalName: server}, krbOpts...)
	if err != nil {
		return nil, err
	}

	supp, err := krbasn1.Marshal(pkinitSuppPubInfo{EType: etypeID, ASReq: asReq, PKASRep: pkASRep})
	if err != nil {
		return nil, err
	}

	oi := otherInfo{PartyUInfo: u, PartyVInfo: v, SuppPubInfo: supp}
	oi.AlgorithmID.Algorithm = k.oid()

	return asn1.Marshal(oi)
}

// DeriveKey is RFC 8636's KDF (SP 800-56A's one-step, with the KDF's
// hash): the key-generation seed of the type from H(counter || Z ||
// OtherInfo), counter from 1, through random-to-key.
func DeriveKey(k KDF, etypeID int32, z, otherInfo []byte) (types.EncryptionKey, error) {
	e, err := kcrypto.GetEtype(etypeID)
	if err != nil {
		return types.EncryptionKey{}, err
	}

	n := e.GetKeySeedBitLength() / 8

	var out []byte

	for counter := uint32(1); len(out) < n; counter++ {
		h := crypto.Hash(k).New()
		h.Write(binary.BigEndian.AppendUint32(nil, counter))
		h.Write(z)
		h.Write(otherInfo)
		out = h.Sum(out)
	}

	return kcrypto.RandomToKey(etypeID, out[:n])
}

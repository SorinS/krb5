package messages

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/crypto/rfc4757"
	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/types"
)

// S4U (MS-SFU), a service acting for a user. With S4U2Self a service asks
// the KDC for a ticket to itself in the name of a user who did not
// authenticate to it (protocol transition); with S4U2Proxy it presents such
// a ticket, or the one the user gave it, and asks for a ticket to another
// service in the user's name (constrained delegation). The KDC decides by
// its own policy: Active Directory's msDS-AllowedToDelegateTo,
// TrustedToAuthForDelegation and msDS-AllowedToActOnBehalfOfOtherIdentity;
// MIT's ok_to_auth_as_delegate (its DB2 back end refuses S4U2Proxy).

// s4uOptUseReplyKeyUsage is S4UUserID's USE_REPLY_KEY_USAGE: the KDC signs
// its echo in usage 27, not 26.
const s4uOptUseReplyKeyUsage = 0x20000000

// paForUser is MS-SFU 2.2.1's PA-FOR-USER.
type paForUser struct {
	UserName    types.PrincipalName `asn1:"explicit,tag:0"`
	UserRealm   string              `asn1:"general,explicit,tag:1"`
	Cksum       types.Checksum      `asn1:"explicit,tag:2"`
	AuthPackage string              `asn1:"general,explicit,tag:3"`
}

// s4uUserID is MS-SFU 2.2.2's S4UUserID, for a user named.
type s4uUserID struct {
	Nonce   int64               `asn1:"explicit,tag:0"`
	CName   types.PrincipalName `asn1:"explicit,optional,tag:1"`
	CRealm  string              `asn1:"general,explicit,tag:2"`
	Cert    []byte              `asn1:"explicit,optional,tag:3"`
	Options asn1.BitString      `asn1:"explicit,optional,tag:4"`
}

// paS4UX509User is MS-SFU 2.2.2's PA-S4U-X509-USER.
type paS4UX509User struct {
	UserID   s4uUserID      `asn1:"explicit,tag:0"`
	Checksum types.Checksum `asn1:"explicit,tag:1"`
}

// An S4UUser is the user of an S4U2Self request, by name or by certificate.
type S4UUser struct {
	Name  types.PrincipalName
	Realm string

	// Cert is the user's certificate (DER), for the KDC to find the user by,
	// Name then being empty: the reply says who it is.
	Cert []byte
}

// byCert is whether the request leaves the name for the KDC to find.
func (u *S4UUser) byCert() bool {
	return len(u.Name.NameString) == 0
}

func marshalKrb(v any) ([]byte, error) {
	return asn1.Marshal(v, asn1.WithMarshalSlicePreserveTypes(true), asn1.WithMarshalSliceAllowStrings(true))
}

// paForUserData is the PA-FOR-USER: an HMAC-MD5 checksum in the TGT's
// session key, whatever its type, of the name type (4 bytes, little
// endian), the name's components, the realm and the auth package.
func (u *S4UUser) paForUserData(sessionKey types.EncryptionKey) (types.PAData, error) {
	const pkg = "Kerberos"

	b := binary.LittleEndian.AppendUint32(nil, uint32(u.Name.NameType))
	for _, s := range u.Name.NameString {
		b = append(b, s...)
	}

	b = append(append(b, u.Realm...), pkg...)

	ck, err := rfc4757.Checksum(sessionKey.KeyValue, keyusage.KERB_NON_KERB_CKSUM_SALT, b)
	if err != nil {
		return types.PAData{}, err
	}

	v, err := marshalKrb(paForUser{UserName: u.Name, UserRealm: u.Realm, AuthPackage: pkg,
		Cksum: types.Checksum{CksumType: chksumtype.KERB_CHECKSUM_HMAC_MD5, Checksum: ck}})
	if err != nil {
		return types.PAData{}, err
	}

	return types.PAData{PADataType: patype.PA_FOR_USER, PADataValue: v}, nil
}

// paS4UData is the PA-S4U-X509-USER: S4UUserID with the request's nonce,
// its checksum in the subkey. False for an old type's subkey, whose
// checksum would be unkeyed (MS-SFU's RSA-MD4): PA-FOR-USER alone then, which
// cannot carry a certificate.
func (u *S4UUser) paS4UData(subkey types.EncryptionKey, nonce int) (types.PAData, bool, error) {
	if subkey.KeyType == etypeID.RC4_HMAC || subkey.KeyType == etypeID.DES3_CBC_SHA1_KD {
		if u.byCert() {
			return types.PAData{}, false, fmt.Errorf("S4U2Self by certificate with a session key of type %d: its checksum would not be keyed", subkey.KeyType)
		}

		return types.PAData{}, false, nil
	}

	id := s4uUserID{Nonce: int64(uint32(nonce)), CName: u.Name, CRealm: u.Realm, Cert: u.Cert, Options: types.NewKrbFlags()}
	binary.BigEndian.PutUint32(id.Options.Bytes, s4uOptUseReplyKeyUsage)

	der, err := marshalKrb(id)
	if err != nil {
		return types.PAData{}, false, err
	}

	et, err := crypto.GetEtype(subkey.KeyType)
	if err != nil {
		return types.PAData{}, false, err
	}

	ck, err := et.GetChecksumHash(subkey.KeyValue, der, keyusage.KEY_USAGE_PA_S4U_X509_USER_REQUEST)
	if err != nil {
		return types.PAData{}, false, err
	}

	v, err := marshalKrb(paS4UX509User{UserID: id, Checksum: types.Checksum{CksumType: et.GetHashID(), Checksum: ck}})
	if err != nil {
		return types.PAData{}, false, err
	}

	return types.PAData{PADataType: patype.PA_FOR_X509_USER, PADataValue: v}, true, nil
}

// NewS4U2SelfReqAt is the TGS request of S4U2Self: for a ticket to service
// (the TGT's own client) in user's name. It asks for a forwardable ticket,
// which S4U2Proxy needs; the KDC gives one only if the TGT is and policy
// lets the service (see client.GetServiceTicketForUser).
func NewS4U2SelfReqAt(service types.PrincipalName, paRealm, kdcRealm string, c *config.Config, tgt Ticket, sessionKey types.EncryptionKey, user S4UUser, now time.Time) (TGSReq, error) {
	if user.byCert() && len(user.Cert) == 0 {
		return TGSReq{}, errors.New("an S4U2Self request needs a user's name or certificate")
	}

	a, err := tgsReq(service, service, kdcRealm, false, c, now)
	if err != nil {
		return a, err
	}

	types.SetFlag(&a.ReqBody.KDCOptions, flags.Forwardable)
	types.SetFlag(&a.ReqBody.KDCOptions, flags.Canonicalize)
	a.S4UUser = &user
	err = a.SetPAData(paRealm, tgt, sessionKey, now)

	return a, err
}

// NewS4U2ProxyReqAt is the TGS request of S4U2Proxy: for a ticket to sname
// in the name of evidence's client, evidence being a ticket to the service
// asking (from S4U2Self, or the user's own). It asks for resource-based
// delegation too (PA-PAC-OPTIONS), which a KDC not doing it ignores.
func NewS4U2ProxyReqAt(service types.PrincipalName, paRealm, kdcRealm string, c *config.Config, tgt Ticket, sessionKey types.EncryptionKey, sname types.PrincipalName, evidence Ticket, now time.Time) (TGSReq, error) {
	a, err := tgsReq(service, sname, kdcRealm, false, c, now)
	if err != nil {
		return a, err
	}

	types.SetFlag(&a.ReqBody.KDCOptions, flags.CNameInAdditionalTicket)
	types.SetFlag(&a.ReqBody.KDCOptions, flags.Canonicalize)
	a.ReqBody.AdditionalTickets = []Ticket{evidence}

	pacOptions, err := types.NewPAPACOptions(types.PACOptionClaims, types.PACOptionResourceBasedConstrained)
	if err != nil {
		return a, err
	}

	a.PAData = types.PADataSequence{pacOptions}
	err = a.SetPAData(paRealm, tgt, sessionKey, now)

	return a, err
}

// IsS4U2Proxy is whether the request is S4U2Proxy's.
func (k *TGSReq) IsS4U2Proxy() bool {
	return types.IsFlagSet(&k.ReqBody.KDCOptions, flags.CNameInAdditionalTicket)
}

// VerifyS4U checks the reply to an S4U2Self request as MIT does: the client
// is the user asked for (the KDC may rewrite an enterprise name), and when
// the KDC echoed PA-S4U-X509-USER (an old KDC need not), the echo has our
// nonce, the user, and a keyed checksum in the request's subkey. A user found
// by certificate has only that echo to say who it is, so it must be there.
// It needs the reply's FAST padata in place of its own, when armored.
func (k *TGSRep) VerifyS4U(tgsReq TGSReq) error {
	u := tgsReq.S4UUser
	if u == nil {
		return nil
	}

	byCert := u.byCert()
	if byCert && k.CRealm != u.Realm {
		return fmt.Errorf("the S4U2Self reply is for a user of %s, not %s", k.CRealm, u.Realm)
	}

	rewritable := byCert || u.Name.NameType == nametype.KRB_NT_ENTERPRISE
	if !rewritable && (!k.CName.Equal(u.Name) || k.CRealm != u.Realm) {
		return fmt.Errorf("the S4U2Self reply is for %s@%s, not %s@%s", k.CName.PrincipalNameString(), k.CRealm, u.Name.PrincipalNameString(), u.Realm)
	}

	var echoed bool

	for _, pa := range k.PAData {
		if pa.PADataType != patype.PA_FOR_X509_USER {
			continue
		}

		var echo paS4UX509User
		if _, err := asn1.Unmarshal(pa.PADataValue, &echo, asn1.WithUnmarshalAllowTypeGeneralString(true)); err != nil {
			return fmt.Errorf("the KDC's PA-S4U-X509-USER: %w", err)
		}

		if uint32(echo.UserID.Nonce) != uint32(tgsReq.ReqBody.Nonce) {
			return errors.New("the KDC's PA-S4U-X509-USER is not for our request (nonce)")
		}

		der, err := marshalKrb(echo.UserID)
		if err != nil {
			return err
		}

		usage := uint32(keyusage.KEY_USAGE_PA_S4U_X509_USER_REQUEST)
		if len(echo.UserID.Options.Bytes) >= 4 && binary.BigEndian.Uint32(echo.UserID.Options.Bytes)&s4uOptUseReplyKeyUsage != 0 {
			usage = keyusage.KEY_USAGE_PA_S4U_X509_USER_REPLY
		}

		et, err := crypto.GetChksumEtype(echo.Checksum.CksumType)
		if err != nil || et.GetETypeID() != tgsReq.SubKey.KeyType {
			return fmt.Errorf("the KDC's PA-S4U-X509-USER has checksum type %d", echo.Checksum.CksumType)
		}

		if !et.VerifyChecksum(tgsReq.SubKey.KeyValue, der, echo.Checksum.Checksum, usage) {
			return errors.New("the KDC's PA-S4U-X509-USER checksum does not check")
		}

		if !rewritable && !echo.UserID.CName.Equal(u.Name) {
			return errors.New("the KDC's PA-S4U-X509-USER names another user")
		}

		if len(echo.UserID.CName.NameString) == 0 || !k.CName.Equal(echo.UserID.CName) {
			return errors.New("the S4U2Self reply's client is not the one the KDC's PA-S4U-X509-USER names")
		}

		echoed = true
	}

	if byCert && !echoed {
		return errors.New("the S4U2Self reply to a request by certificate has no PA-S4U-X509-USER")
	}

	return nil
}

// Package pkinit is PKINIT (RFC 4556), the client's side: a TGT from an
// X.509 certificate and its key instead of a password, or anonymously (RFC
// 8062), the reply key agreed by Diffie-Hellman.
//
// The exchange. The KDC lists PA-PK-AS-REQ in its PREAUTH_REQUIRED error,
// with a freshness token (RFC 8070) when it has one. The client sends an
// AuthPack in a CMS SignedData signed by its key, its certificate (and
// those up to its CA) beside it: a PKAuthenticator (time, a nonce, the
// SHA-1 of the KDC-REQ-BODY, the freshness token), its Diffie-Hellman
// public value with the group's parameters, the signature algorithms it
// takes and the KDFs (RFC 8636). The KDC answers with a PA-PK-AS-REP: its
// public value and our nonce in a SignedData signed by the KDC's key, and
// the KDF it picked. The reply key is that KDF over the shared secret (with
// the client's and the KDC's names, the request and the reply in it), or
// RFC 4556's octetstring2key when the KDC names none.
//
// The KDC's certificate must chain to an anchor (pkinit_anchors, with the
// SignedData's other certificates and pkinit_pool as intermediates) and
// name the KDC: an id-pkinit-san of krbtgt/REALM@REALM, or (with
// pkinit_kdc_hostname) a dNSName of that host and then the EKU that
// pkinit_eku_checking asks for (id-pkinit-KPKdc by default; kpServerAuth;
// none), as MIT checks it.
//
// Not done: RSA key transport (encKeyPack; MIT 1.22's KDC refuses it),
// reused DH keys (clientDHNonce), smart cards (PKCS #11), PKCS #12 files.
package pkinit

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	krbasn1 "github.com/go-krb5/x/encoding/asn1"

	"github.com/SorinS/krb5/config"
	kcrypto "github.com/SorinS/krb5/crypto"
	"github.com/SorinS/krb5/iana/errorcode"
	"github.com/SorinS/krb5/types"
)

var (
	oidPKINITAuthData  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 1}
	oidPKINITDHKeyData = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 2}
	oidPKINITKPKdc     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 5}
	oidPKINITSAN       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 2}
	oidSAN             = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// KeyUsagePAPKINITKX is the key usage of PA-PKINIT-KX (RFC 8062 7).
const KeyUsagePAPKINITKX = 44

// An Error is the client's refusal of a KDC's PKINIT answer, as the KDC
// error code that names it.
type Error struct {
	Code int32
	Err  error
}

func (e *Error) Error() string {
	return fmt.Sprintf("pkinit: %s: %v", errorcode.Lookup(e.Code), e.Err)
}

func (e *Error) Unwrap() error {
	return e.Err
}

func pkErr(code int32, format string, a ...any) error {
	return &Error{Code: code, Err: fmt.Errorf(format, a...)}
}

// An Identity is a certificate and its key, and the certificates up to
// its CA (sent with it).
type Identity struct {
	Certificate *x509.Certificate
	Chain       []*x509.Certificate
	Key         crypto.Signer
}

// LoadIdentity reads an identity in MIT's X509_user_identity syntax:
// FILE:cert[,key], PEM (the key in the certificate's file when not named;
// the certificates other than the key's are its chain).
func LoadIdentity(spec string) (*Identity, error) {
	if !strings.HasPrefix(spec, "FILE:") {
		return nil, fmt.Errorf("pkinit: identity %q: only FILE:cert[,key] is supported", spec)
	}

	certPath, keyPath, ok := strings.Cut(spec[len("FILE:"):], ",")
	if !ok {
		keyPath = certPath
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	certs, err := certsOf(certPEM)
	if err != nil {
		return nil, err
	}

	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, err
	}

	return NewIdentity(certs, key)
}

// NewIdentity is the identity of key among certs: the certificate whose
// public key is the key's, the others its chain.
func NewIdentity(certs []*x509.Certificate, key crypto.Signer) (*Identity, error) {
	id := &Identity{Key: key}

	type equaler interface{ Equal(crypto.PublicKey) bool }

	for _, c := range certs {
		if pk, ok := key.Public().(equaler); ok && id.Certificate == nil && pk.Equal(c.PublicKey) {
			id.Certificate = c
		} else {
			id.Chain = append(id.Chain, c)
		}
	}

	if id.Certificate == nil {
		return nil, errors.New("pkinit: no certificate of the key")
	}

	return id, nil
}

// certsOf are the certificates of a file: PEM (every CERTIFICATE block)
// or DER.
func certsOf(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate

	for rest := b; ; {
		var blk *pem.Block

		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}

		if blk.Type != "CERTIFICATE" {
			continue
		}

		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}

		out = append(out, c)
	}

	if len(out) > 0 {
		return out, nil
	}

	return x509.ParseCertificates(b)
}

func parseKey(b []byte) (crypto.Signer, error) {
	for rest := b; ; {
		var blk *pem.Block

		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}

		var (
			k   any
			err error
		)

		switch blk.Type {
		case "PRIVATE KEY":
			k, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
		case "RSA PRIVATE KEY":
			k, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
		case "EC PRIVATE KEY":
			k, err = x509.ParseECPrivateKey(blk.Bytes)
		default:
			continue
		}

		if err != nil {
			return nil, err
		}

		switch s := k.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return s.(crypto.Signer), nil
		}

		return nil, fmt.Errorf("pkinit: unsupported key %T", k)
	}

	return nil, errors.New("pkinit: no private key in the file")
}

// EKUCheck is how the client checks the KDC certificate's EKU when it names
// the KDC by host name (pkinit_eku_checking).
type EKUCheck int

// The EKU checks.
const (
	EKUKDC EKUCheck = iota
	EKUServerAuth
	EKUNone
)

// Trust is what the client trusts of KDC certificates: anchors,
// intermediates, the KDC host names taken (pkinit_kdc_hostname) and the
// EKU check.
type Trust struct {
	Anchors       *x509.CertPool
	Intermediates []*x509.Certificate
	KDCHostnames  []string
	EKU           EKUCheck
}

// realmValues are a realm's values of a PKINIT relation: [realms] first,
// then [libdefaults].
func realmValues(cfg *config.Config, realm, name string) []string {
	for _, r := range cfg.Realms {
		if r.Realm == realm {
			if v := r.Values[name]; len(v) > 0 {
				return v
			}
		}
	}

	return cfg.LibDefaults.Values[name]
}

// TrustFromConfig is the trust of a realm's KDC certificates as krb5.conf
// sets it: pkinit_anchors and pkinit_pool (FILE:path, a bundle, or
// DIR:path, every file in it), pkinit_kdc_hostname, pkinit_eku_checking.
func TrustFromConfig(cfg *config.Config, realm string) (*Trust, error) {
	t := &Trust{Anchors: x509.NewCertPool()}

	anchors, err := loadCerts(realmValues(cfg, realm, "pkinit_anchors"))
	if err != nil {
		return nil, err
	}

	if len(anchors) == 0 {
		return nil, pkErr(errorcode.KDC_ERROR_KDC_NOT_TRUSTED, "no pkinit_anchors for %s", realm)
	}

	for _, c := range anchors {
		t.Anchors.AddCert(c)
	}

	if t.Intermediates, err = loadCerts(realmValues(cfg, realm, "pkinit_pool")); err != nil {
		return nil, err
	}

	t.KDCHostnames = realmValues(cfg, realm, "pkinit_kdc_hostname")

	switch v := realmValues(cfg, realm, "pkinit_eku_checking"); {
	case len(v) > 0 && v[0] == "kpServerAuth":
		t.EKU = EKUServerAuth
	case len(v) > 0 && v[0] == "none":
		t.EKU = EKUNone
	}

	return t, nil
}

func loadCerts(values []string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate

	for _, v := range values {
		switch {
		case strings.HasPrefix(v, "FILE:"):
			b, err := os.ReadFile(v[len("FILE:"):])
			if err != nil {
				return nil, err
			}

			cs, err := certsOf(b)
			if err != nil {
				return nil, err
			}

			out = append(out, cs...)
		case strings.HasPrefix(v, "DIR:"):
			d := v[len("DIR:"):]

			entries, err := os.ReadDir(d)
			if err != nil {
				return nil, err
			}

			for _, e := range entries {
				if b, err := os.ReadFile(filepath.Join(d, e.Name())); err == nil {
					if cs, err := certsOf(b); err == nil {
						out = append(out, cs...)
					}
				}
			}
		default:
			return nil, fmt.Errorf("pkinit: certificate location %q: only FILE: and DIR: are supported", v)
		}
	}

	return out, nil
}

// GroupFromConfig is the group to start with: pkinit_dh_min_bits (2048 by
// default).
func GroupFromConfig(cfg *config.Config, realm string) Group {
	if v := realmValues(cfg, realm, "pkinit_dh_min_bits"); len(v) > 0 {
		return GroupNamed(v[0])
	}

	return MODP2048
}

// KDFsFromConfig are the KDFs to offer: pkinit_kdfs (ours, not MIT's: hash
// names among sha1 sha256 sha384 sha512, or none to offer none and have RFC
// 4556's octetstring2key), DefaultKDFs when not set.
func KDFsFromConfig(cfg *config.Config, realm string) []KDF {
	v := realmValues(cfg, realm, "pkinit_kdfs")
	if len(v) == 0 {
		return DefaultKDFs
	}

	out := []KDF{}

	for _, w := range strings.Fields(strings.Join(v, " ")) {
		switch w {
		case "sha1":
			out = append(out, KDFSHA1)
		case "sha256":
			out = append(out, KDFSHA256)
		case "sha384":
			out = append(out, KDFSHA384)
		case "sha512":
			out = append(out, KDFSHA512)
		}
	}

	return out
}

// --- Messages ---------------------------------------------------------------

func explicit(tag int, b []byte) []byte {
	out, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: b})
	return out
}

func implicit(tag int, b []byte) []byte {
	out, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, Bytes: b})
	return out
}

func sequence(parts ...[]byte) []byte {
	out, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: bytes.Join(parts, nil)})
	return out
}

type pkAuthenticator struct {
	Cusec          int       `asn1:"explicit,tag:0"`
	Ctime          time.Time `asn1:"generalized,explicit,tag:1"`
	Nonce          int64     `asn1:"explicit,tag:2"`
	PAChecksum     []byte    `asn1:"explicit,optional,tag:3"`
	FreshnessToken []byte    `asn1:"explicit,optional,tag:4"`
}

// supportedCMSTypes are the signature algorithms we take from the KDC,
// best first.
var supportedCMSTypes = []pkix.AlgorithmIdentifier{
	{Algorithm: oidECDSASHA512}, {Algorithm: oidECDSASHA384}, {Algorithm: oidECDSASHA256},
	{Algorithm: oidSHA512WithRSA, Parameters: asn1.NullRawValue},
	{Algorithm: oidSHA384WithRSA, Parameters: asn1.NullRawValue},
	{Algorithm: oidSHA256WithRSA, Parameters: asn1.NullRawValue},
}

// AuthPack is the AuthPack (RFC 4556 3.2.1, RFC 8636 6, RFC 8070 4) of a
// request at the time now: body is the KDC-REQ-BODY its checksum covers;
// freshness the KDC's token, if any; kdfs the KDFs to offer (none: the
// field left out).
func AuthPack(now time.Time, nonce int, body, freshness []byte, dh *DHKey, kdfs []KDF) ([]byte, error) {
	ck := sha1.Sum(body)
	t := now.UTC()

	pa, err := krbasn1.Marshal(pkAuthenticator{
		Cusec: t.Nanosecond() / 1000, Ctime: t.Truncate(time.Second), Nonce: int64(uint32(nonce)),
		PAChecksum: ck[:], FreshnessToken: freshness,
	})
	if err != nil {
		return nil, err
	}

	cms, err := asn1.Marshal(supportedCMSTypes)
	if err != nil {
		return nil, err
	}

	parts := [][]byte{explicit(0, pa), explicit(1, dh.SPKI), explicit(2, cms)}

	if len(kdfs) > 0 {
		var ids [][]byte

		for _, k := range kdfs {
			o, err := asn1.Marshal(k.oid())
			if err != nil {
				return nil, err
			}

			ids = append(ids, sequence(explicit(0, o)))
		}

		parts = append(parts, explicit(4, sequence(ids...)))
	}

	return sequence(parts...), nil
}

// PAPKASReq is PA-PK-AS-REQ's value: the AuthPack signed by the identity's
// key, or unsigned when id is nil (anonymous).
func PAPKASReq(authPack []byte, id *Identity) ([]byte, error) {
	var (
		signed []byte
		err    error
	)

	if id == nil {
		signed, err = Unsigned(oidPKINITAuthData, authPack)
	} else {
		signed, err = Sign(oidPKINITAuthData, authPack, id.Key, id.Certificate, id.Chain)
	}

	if err != nil {
		return nil, err
	}

	// signedAuthPack [0] IMPLICIT OCTET STRING.
	return sequence(implicit(0, signed)), nil
}

// pkASRep is a PA-PK-AS-REP with DHRepInfo: the dhSignedData (a
// ContentInfo) and the KDF the KDC picked (KDFOld: none named).
type pkASRep struct {
	signedData []byte
	kdf        KDF
}

func parsePKASRep(v []byte) (pkASRep, error) {
	var choice asn1.RawValue
	if rest, err := asn1.Unmarshal(v, &choice); err != nil || len(rest) > 0 || choice.Class != asn1.ClassContextSpecific {
		return pkASRep{}, errors.New("pkinit: malformed PA-PK-AS-REP")
	}

	if choice.Tag == 1 {
		return pkASRep{}, pkErr(errorcode.KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED, "the KDC used RSA key transport, which we did not offer")
	}

	if choice.Tag != 0 || !choice.IsCompound {
		return pkASRep{}, errors.New("pkinit: malformed PA-PK-AS-REP")
	}

	var dhRep asn1.RawValue
	if rest, err := asn1.Unmarshal(choice.Bytes, &dhRep); err != nil || len(rest) > 0 || dhRep.Tag != asn1.TagSequence {
		return pkASRep{}, errors.New("pkinit: malformed DHRepInfo")
	}

	out := pkASRep{kdf: KDFOld}
	last := -1

	for rest := dhRep.Bytes; len(rest) > 0; {
		var f asn1.RawValue

		var err error
		if rest, err = asn1.Unmarshal(rest, &f); err != nil || f.Class != asn1.ClassContextSpecific || f.Tag <= last {
			return pkASRep{}, errors.New("pkinit: malformed DHRepInfo")
		}

		last = f.Tag

		switch f.Tag {
		case 0: // dhSignedData [0] IMPLICIT OCTET STRING
			if f.IsCompound {
				return pkASRep{}, errors.New("pkinit: malformed DHRepInfo")
			}

			out.signedData = f.Bytes
		case 1: // serverDHNonce: reused keys, which we did not offer
			return pkASRep{}, errors.New("pkinit: a serverDHNonce, for DH keys we do not reuse")
		case 2: // kdf [2] KDFAlgorithmId ::= SEQUENCE { kdf-id [0] OID }
			var id struct {
				ID asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
			}

			if _, err := asn1.Unmarshal(f.Bytes, &id); err != nil {
				return pkASRep{}, errors.New("pkinit: malformed KDFAlgorithmId")
			}

			k, ok := kdfOf(id.ID)
			if !ok {
				return pkASRep{}, pkErr(errorcode.KDC_ERR_NO_ACCEPTABLE_KDF, "the KDC's KDF %v is not one we know", id.ID)
			}

			out.kdf = k
		}
	}

	if out.signedData == nil {
		return pkASRep{}, errors.New("pkinit: DHRepInfo without dhSignedData")
	}

	return out, nil
}

type kdcDHKeyInfo struct {
	SubjectPublicKey asn1.BitString `asn1:"explicit,tag:0"`
	Nonce            int64          `asn1:"explicit,tag:1"`
	DHKeyExpiration  asn1.RawValue  `asn1:"explicit,optional,tag:2"`
}

// --- The KDC's certificate ---------------------------------------------------

// sanNames is whether the certificate's SAN holds an id-pkinit-san naming
// the principal (the name type not compared, as MIT does not).
func sanNames(c *x509.Certificate, name types.PrincipalName, realm string) bool {
	for _, ext := range c.Extensions {
		if !ext.Id.Equal(oidSAN) {
			continue
		}

		var gns []asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &gns); err != nil {
			return false
		}

		for _, gn := range gns {
			// otherName [0] IMPLICIT SEQUENCE { type-id, [0] EXPLICIT value }.
			if gn.Class != asn1.ClassContextSpecific || gn.Tag != 0 || !gn.IsCompound {
				continue
			}

			var on struct {
				TypeID asn1.ObjectIdentifier
				Value  asn1.RawValue `asn1:"explicit,tag:0"`
			}

			if _, err := asn1.Unmarshal(append([]byte{0x30}, gn.FullBytes[1:]...), &on); err != nil || !on.TypeID.Equal(oidPKINITSAN) {
				continue
			}

			var kpn krb5PrincipalName
			if _, err := krbasn1.Unmarshal(on.Value.Bytes, &kpn, krbasn1.WithUnmarshalAllowTypeGeneralString(true)); err != nil {
				continue
			}

			if kpn.Realm == realm && kpn.PrincipalName.Equal(name) {
				return true
			}
		}
	}

	return false
}

func hasEKU(c *x509.Certificate, check EKUCheck) bool {
	switch check {
	case EKUNone:
		return true
	case EKUServerAuth:
		for _, u := range c.ExtKeyUsage {
			if u == x509.ExtKeyUsageServerAuth {
				return true
			}
		}

		return false
	}

	for _, u := range c.UnknownExtKeyUsage {
		if u.Equal(oidPKINITKPKdc) {
			return true
		}
	}

	return false
}

// CheckKDC checks a KDC's SignedData: its signer chains to an anchor at the
// time now, is the KDC of the realm, and signed the content, of type
// id-pkinit-DHKeyData. It returns the content.
func CheckKDC(sdDER []byte, trust *Trust, realm string, now time.Time) ([]byte, error) {
	sd, err := ParseSignedData(sdDER)
	if err != nil {
		return nil, err
	}

	if !sd.ContentType.Equal(oidPKINITDHKeyData) {
		return nil, fmt.Errorf("pkinit: the KDC signed content of type %v", sd.ContentType)
	}

	signer, err := sd.Verify()
	if errors.Is(err, ErrUnsupportedAlgorithm) {
		return nil, pkErr(errorcode.KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED, "%v", err)
	} else if err != nil {
		return nil, pkErr(errorcode.KDC_ERROR_INVALID_SIG, "%v", err)
	}

	inters := x509.NewCertPool()
	for _, c := range append(append([]*x509.Certificate(nil), sd.Certificates...), trust.Intermediates...) {
		inters.AddCert(c)
	}

	if _, err := signer.Verify(x509.VerifyOptions{Roots: trust.Anchors, Intermediates: inters, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, pkErr(errorcode.KDC_ERROR_KDC_NOT_TRUSTED, "the KDC's certificate: %v", err)
	}

	// The KDC's name: its id-pkinit-san, which needs no EKU (MIT: the CA
	// certified it as the KDC), or a host name we were told to take, with
	// the EKU.
	krbtgt := types.PrincipalName{NameType: 2, NameString: []string{"krbtgt", realm}}
	if !sanNames(signer, krbtgt, realm) {
		byHost := false

		for _, h := range trust.KDCHostnames {
			for _, d := range signer.DNSNames {
				byHost = byHost || strings.EqualFold(d, h)
			}
		}

		if !byHost {
			return nil, pkErr(errorcode.KDC_ERR_KDC_NAME_MISMATCH, "the KDC's certificate does not name krbtgt/%s@%s", realm, realm)
		}

		if !hasEKU(signer, trust.EKU) {
			return nil, pkErr(errorcode.KDC_ERR_INCONSISTENT_KEY_PURPOSE, "the KDC's certificate lacks the EKU")
		}
	}

	return sd.Content, nil
}

// --- The reply key -------------------------------------------------------------

// A Request is what the client keeps of its PKINIT request for the reply:
// the DH key, the nonce and the KDFs offered.
type Request struct {
	DH    *DHKey
	Nonce int
	KDFs  []KDF
}

// ReplyKey is the reply key from the KDC's PA-PK-AS-REP (repValue): checks
// the KDC's signed key info (its certificate, its signature, our nonce),
// finds the shared secret, and derives the key of the type by the KDF the
// KDC named (one of those we offered) or, when it named none, by
// octetstring2key. asReq is the request as sent; client, crealm, server
// and srealm its names (the client's realm is WELLKNOWN:ANONYMOUS when
// anonymous).
func (r *Request) ReplyKey(repValue []byte, trust *Trust, etypeID int32, client types.PrincipalName, crealm string,
	server types.PrincipalName, srealm string, asReq []byte, now time.Time) (types.EncryptionKey, error) {
	rep, err := parsePKASRep(repValue)
	if err != nil {
		return types.EncryptionKey{}, err
	}

	info, err := CheckKDC(rep.signedData, trust, srealm, now)
	if err != nil {
		return types.EncryptionKey{}, err
	}

	var ki kdcDHKeyInfo
	if rest, err := asn1.Unmarshal(info, &ki); err != nil || len(rest) > 0 || ki.SubjectPublicKey.BitLength%8 != 0 {
		return types.EncryptionKey{}, errors.New("pkinit: malformed KDCDHKeyInfo")
	}

	if len(ki.DHKeyExpiration.FullBytes) > 0 {
		return types.EncryptionKey{}, errors.New("pkinit: a dhKeyExpiration, for DH keys we do not reuse")
	}

	if uint32(ki.Nonce) != uint32(r.Nonce) || ki.Nonce < 0 || ki.Nonce > 0xffffffff {
		return types.EncryptionKey{}, errors.New("pkinit: the KDC's key info is not for our request (nonce)")
	}

	z, err := r.DH.Shared(ki.SubjectPublicKey.Bytes)
	if err != nil {
		return types.EncryptionKey{}, pkErr(errorcode.KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED, "%v", err)
	}

	if rep.kdf == KDFOld {
		return OctetString2Key(etypeID, z)
	}

	offered := false
	for _, k := range r.KDFs {
		offered = offered || k == rep.kdf
	}

	if !offered {
		return types.EncryptionKey{}, pkErr(errorcode.KDC_ERR_NO_ACCEPTABLE_KDF, "the KDC's KDF was not offered")
	}

	oi, err := OtherInfo(rep.kdf, client, crealm, server, srealm, etypeID, asReq, repValue)
	if err != nil {
		return types.EncryptionKey{}, err
	}

	return DeriveKey(rep.kdf, etypeID, z, oi)
}

// CheckKX is RFC 8062 7's check of PA-PKINIT-KX (kx, the padata's value):
// the KDC's contribution key, encrypted in the reply key, combined with the
// reply key by KRB-FX-CF2(contribution, "PKINIT", reply key, "KEYEXCHANGE")
// must be the ticket's session key.
func CheckKX(kx []byte, replyKey, sessionKey types.EncryptionKey) error {
	var ed types.EncryptedData
	if err := ed.Unmarshal(kx); err != nil {
		return err
	}

	plain, err := kcrypto.DecryptEncPart(ed, replyKey, KeyUsagePAPKINITKX)
	if err != nil {
		return err
	}

	var contribution types.EncryptionKey
	if _, err := krbasn1.Unmarshal(plain, &contribution); err != nil {
		return err
	}

	k, err := kcrypto.CF2(contribution, "PKINIT", replyKey, "KEYEXCHANGE")
	if err != nil {
		return err
	}

	if k.KeyType != sessionKey.KeyType || !bytes.Equal(k.KeyValue, sessionKey.KeyValue) {
		return errors.New("pkinit: PA-PKINIT-KX does not give the session key")
	}

	return nil
}

// TDDHParameters is the value of the first TD-DH-PARAMETERS in a KRB-ERROR's
// e-data (TYPED-DATA: SEQUENCE OF { data-type [0], data-value [1] }); false
// when there is none.
func TDDHParameters(edata []byte) ([]byte, bool) {
	var tds []struct {
		Type  int32  `asn1:"explicit,tag:0"`
		Value []byte `asn1:"explicit,optional,tag:1"`
	}

	if _, err := asn1.Unmarshal(edata, &tds); err != nil {
		return nil, false
	}

	for _, td := range tds {
		if td.Type == 109 {
			return td.Value, true
		}
	}

	return nil, false
}

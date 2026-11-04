package pkinit

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// CMS SignedData (RFC 5652), what PKINIT needs of it: the client signs its
// AuthPack (or sends it unsigned, anonymous), and checks the KDC's signed
// DH key info. Signed attributes are content-type and message-digest; the
// signer is named by issuer and serial number (or, read, by subject key
// identifier).

var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA1WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECDSASHA256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSASHA384   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSASHA512   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidEd25519       = asn1.ObjectIdentifier{1, 3, 101, 112}
)

// ErrSignature is a SignedData whose signature, digest or signer does not
// check.
var ErrSignature = errors.New("pkinit: CMS signature does not check")

// ErrUnsupportedAlgorithm is a SignedData signed with an algorithm this
// package does not take.
var ErrUnsupportedAlgorithm = errors.New("pkinit: CMS algorithm not supported")

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0"` // [0] EXPLICIT, the RawValue's own tag
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,tag:0"`
}

type rawSet struct {
	Raw asn1.RawContent
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        rawSet `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      rawSet `asn1:"optional,tag:1"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo encapContentInfo
	Certificates     rawSet       `asn1:"optional,tag:0"`
	CRLs             rawSet       `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo `asn1:"set"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

// digestOf is the hash a digest algorithm OID names.
func digestOf(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	switch {
	case oid.Equal(oidSHA1):
		return crypto.SHA1, true
	case oid.Equal(oidSHA256):
		return crypto.SHA256, true
	case oid.Equal(oidSHA384):
		return crypto.SHA384, true
	case oid.Equal(oidSHA512):
		return crypto.SHA512, true
	}

	return 0, false
}

func digestOID(h crypto.Hash) asn1.ObjectIdentifier {
	switch h {
	case crypto.SHA384:
		return oidSHA384
	case crypto.SHA512:
		return oidSHA512
	case crypto.SHA1:
		return oidSHA1
	}

	return oidSHA256
}

// signatureFor is the hash and signature algorithm a key signs with: PKCS
// #1 v1.5 with SHA-256 for RSA, ECDSA with its curve's hash, Ed25519.
func signatureFor(key crypto.Signer) (crypto.Hash, pkix.AlgorithmIdentifier, error) {
	switch k := key.Public().(type) {
	case *rsa.PublicKey:
		return crypto.SHA256, pkix.AlgorithmIdentifier{Algorithm: oidSHA256WithRSA, Parameters: asn1.NullRawValue}, nil
	case *ecdsa.PublicKey:
		switch k.Curve.Params().BitSize {
		case 384:
			return crypto.SHA384, pkix.AlgorithmIdentifier{Algorithm: oidECDSASHA384}, nil
		case 521:
			return crypto.SHA512, pkix.AlgorithmIdentifier{Algorithm: oidECDSASHA512}, nil
		}

		return crypto.SHA256, pkix.AlgorithmIdentifier{Algorithm: oidECDSASHA256}, nil
	case ed25519.PublicKey:
		return crypto.SHA512, pkix.AlgorithmIdentifier{Algorithm: oidEd25519}, nil
	}

	return 0, pkix.AlgorithmIdentifier{}, ErrUnsupportedAlgorithm
}

func digest(h crypto.Hash, b []byte) []byte {
	d := h.New()
	d.Write(b)

	return d.Sum(nil)
}

// signedAttrs is the DER of the SET OF the content-type and
// message-digest attributes (in DER's order).
func signedAttrs(contentType asn1.ObjectIdentifier, md []byte) ([]byte, error) {
	ct, err := asn1.Marshal(contentType)
	if err != nil {
		return nil, err
	}

	mdv, err := asn1.Marshal(md)
	if err != nil {
		return nil, err
	}

	attrs := []attribute{
		{Type: oidContentType, Values: []asn1.RawValue{{FullBytes: ct}}},
		{Type: oidMessageDigest, Values: []asn1.RawValue{{FullBytes: mdv}}},
	}

	var encs [][]byte

	for _, a := range attrs {
		b, err := asn1.Marshal(a)
		if err != nil {
			return nil, err
		}

		encs = append(encs, b)
	}

	// SET OF: the elements in the order of their encodings.
	if bytes.Compare(encs[0], encs[1]) > 0 {
		encs[0], encs[1] = encs[1], encs[0]
	}

	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: bytes.Join(encs, nil)})
}

// Sign is a ContentInfo with a SignedData of content (of contentType),
// signed by key, whose certificate is cert; chain goes along with it
// (those up to its CA).
func Sign(contentType asn1.ObjectIdentifier, content []byte, key crypto.Signer, cert *x509.Certificate, chain []*x509.Certificate) ([]byte, error) {
	h, sigAlg, err := signatureFor(key)
	if err != nil {
		return nil, err
	}

	attrs, err := signedAttrs(contentType, digest(h, content))
	if err != nil {
		return nil, err
	}

	var sig []byte
	if _, ok := key.Public().(ed25519.PublicKey); ok {
		sig, err = key.Sign(rand.Reader, attrs, crypto.Hash(0))
	} else {
		sig, err = key.Sign(rand.Reader, digest(h, attrs), h)
	}

	if err != nil {
		return nil, err
	}

	ias, err := asn1.Marshal(issuerAndSerial{Issuer: asn1.RawValue{FullBytes: cert.RawIssuer}, Serial: cert.SerialNumber})
	if err != nil {
		return nil, err
	}

	// [0] IMPLICIT SET OF Attribute: the SET's tag replaced.
	implicitAttrs := append([]byte{0xa0}, attrs[1:]...)

	certs := cert.Raw
	for _, c := range chain {
		certs = append(append([]byte(nil), certs...), c.Raw...)
	}

	certsDER, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certs})
	if err != nil {
		return nil, err
	}

	sd := signedData{
		Version:          3,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: digestOID(h)}},
		EncapContentInfo: encapContentInfo{EContentType: contentType, EContent: content},
		Certificates:     rawSet{Raw: certsDER},
		SignerInfos: []signerInfo{{
			Version:            1,
			SID:                asn1.RawValue{FullBytes: ias},
			DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: digestOID(h)},
			SignedAttrs:        rawSet{Raw: implicitAttrs},
			SignatureAlgorithm: sigAlg,
			Signature:          sig,
		}},
	}

	return wrapSignedData(sd)
}

// Unsigned is a ContentInfo with a SignedData of content and no signer
// (RFC 8062 4.1: anonymous PKINIT's AuthPack).
func Unsigned(contentType asn1.ObjectIdentifier, content []byte) ([]byte, error) {
	return wrapSignedData(signedData{
		Version:          3,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{},
		EncapContentInfo: encapContentInfo{EContentType: contentType, EContent: content},
		SignerInfos:      []signerInfo{},
	})
}

func wrapSignedData(sd signedData) ([]byte, error) {
	b, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}

	// A RawValue with FullBytes is written as it is, its field's explicit
	// tag left out: the [0] is built here.
	return asn1.Marshal(contentInfo{ContentType: oidSignedData,
		Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: b}})
}

// SignedData is a parsed SignedData.
type SignedData struct {
	ContentType  asn1.ObjectIdentifier
	Content      []byte
	Certificates []*x509.Certificate
	signers      []signerInfo
}

// ParseSignedData reads a ContentInfo holding a SignedData.
func ParseSignedData(der []byte) (*SignedData, error) {
	var ci contentInfo
	if rest, err := asn1.Unmarshal(der, &ci); err != nil || len(rest) > 0 || !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("pkinit: not a CMS SignedData: %v", err)
	}

	var sd signedData
	if rest, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil || len(rest) > 0 {
		return nil, fmt.Errorf("pkinit: malformed SignedData: %v", err)
	}

	out := &SignedData{ContentType: sd.EncapContentInfo.EContentType, Content: sd.EncapContentInfo.EContent, signers: sd.SignerInfos}

	if len(sd.Certificates.Raw) > 0 {
		var rv asn1.RawValue
		if _, err := asn1.Unmarshal(sd.Certificates.Raw, &rv); err != nil {
			return nil, err
		}

		certs, err := x509.ParseCertificates(rv.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pkinit: the SignedData's certificates: %w", err)
		}

		out.Certificates = certs
	}

	return out, nil
}

// Verify checks the SignedData's one signer: found among its certificates,
// its message digest that of the content, its content type the
// SignedData's, its signature over the signed attributes. It returns the
// signer's certificate (whose chain the caller checks).
func (s *SignedData) Verify() (*x509.Certificate, error) {
	if len(s.signers) != 1 {
		return nil, fmt.Errorf("%w: %d signers", ErrSignature, len(s.signers))
	}

	si := s.signers[0]

	cert, err := s.signer(si.SID)
	if err != nil {
		return nil, err
	}

	h, ok := digestOf(si.DigestAlgorithm.Algorithm)
	if !ok {
		return nil, ErrUnsupportedAlgorithm
	}

	signed := s.Content

	if len(si.SignedAttrs.Raw) > 0 {
		// The signature is over the attributes as a SET (tag 0x31).
		signed = append([]byte{0x31}, si.SignedAttrs.Raw[1:]...)

		var attrs []attribute
		if _, err := asn1.UnmarshalWithParams(signed, &attrs, "set"); err != nil {
			return nil, fmt.Errorf("%w: signed attributes: %v", ErrSignature, err)
		}

		var md, ct bool

		for _, a := range attrs {
			if len(a.Values) != 1 {
				return nil, fmt.Errorf("%w: attribute with %d values", ErrSignature, len(a.Values))
			}

			switch {
			case a.Type.Equal(oidMessageDigest):
				var d []byte
				if _, err := asn1.Unmarshal(a.Values[0].FullBytes, &d); err != nil || !bytes.Equal(d, digest(h, s.Content)) {
					return nil, fmt.Errorf("%w: message digest", ErrSignature)
				}

				md = true
			case a.Type.Equal(oidContentType):
				var o asn1.ObjectIdentifier
				if _, err := asn1.Unmarshal(a.Values[0].FullBytes, &o); err != nil || !o.Equal(s.ContentType) {
					return nil, fmt.Errorf("%w: content type", ErrSignature)
				}

				ct = true
			}
		}

		if !md || !ct {
			return nil, fmt.Errorf("%w: signed attributes lack the digest or content type", ErrSignature)
		}
	}

	if err := checkSignature(cert, si, h, signed); err != nil {
		return nil, err
	}

	return cert, nil
}

// signer is the certificate a SignerIdentifier names.
func (s *SignedData) signer(sid asn1.RawValue) (*x509.Certificate, error) {
	if sid.Class == asn1.ClassContextSpecific && sid.Tag == 0 {
		for _, c := range s.Certificates {
			if len(c.SubjectKeyId) > 0 && bytes.Equal(c.SubjectKeyId, sid.Bytes) {
				return c, nil
			}
		}

		return nil, fmt.Errorf("%w: no certificate of the signer's key identifier", ErrSignature)
	}

	var ias issuerAndSerial
	if _, err := asn1.Unmarshal(sid.FullBytes, &ias); err != nil {
		return nil, fmt.Errorf("%w: signer identifier: %v", ErrSignature, err)
	}

	for _, c := range s.Certificates {
		if bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) && c.SerialNumber.Cmp(ias.Serial) == 0 {
			return c, nil
		}
	}

	return nil, fmt.Errorf("%w: no certificate of the signer's issuer and serial", ErrSignature)
}

func checkSignature(cert *x509.Certificate, si signerInfo, h crypto.Hash, signed []byte) error {
	alg := si.SignatureAlgorithm.Algorithm

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		var sh crypto.Hash

		switch {
		case alg.Equal(oidRSAEncryption):
			sh = h // the hash is the digest algorithm's
		case alg.Equal(oidSHA256WithRSA):
			sh = crypto.SHA256
		case alg.Equal(oidSHA384WithRSA):
			sh = crypto.SHA384
		case alg.Equal(oidSHA512WithRSA):
			sh = crypto.SHA512
		case alg.Equal(oidSHA1WithRSA):
			sh = crypto.SHA1
		default:
			return ErrUnsupportedAlgorithm
		}

		if sh != h || sh == crypto.SHA1 {
			return ErrUnsupportedAlgorithm
		}

		if rsa.VerifyPKCS1v15(pub, sh, digest(sh, signed), si.Signature) != nil {
			return ErrSignature
		}
	case *ecdsa.PublicKey:
		var sh crypto.Hash

		switch {
		case alg.Equal(oidECDSASHA256):
			sh = crypto.SHA256
		case alg.Equal(oidECDSASHA384):
			sh = crypto.SHA384
		case alg.Equal(oidECDSASHA512):
			sh = crypto.SHA512
		default:
			return ErrUnsupportedAlgorithm
		}

		if !ecdsa.VerifyASN1(pub, digest(sh, signed), si.Signature) {
			return ErrSignature
		}
	case ed25519.PublicKey:
		if !alg.Equal(oidEd25519) || !ed25519.Verify(pub, signed, si.Signature) {
			return ErrSignature
		}
	default:
		return ErrUnsupportedAlgorithm
	}

	return nil
}

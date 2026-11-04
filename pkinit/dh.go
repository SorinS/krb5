package pkinit

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// A Group is a Diffie-Hellman group PKINIT agrees the reply key in: MODP
// 2048 and 4096 (RFC 3526 groups 14 and 16, as MIT names them by size),
// P-256, P-384 and P-521 (RFC 5349; the secret is the shared point's
// x-coordinate). The constants are in MIT's order of strength.
type Group int

// The groups.
const (
	MODP2048 Group = iota + 1
	P256
	MODP4096
	P384
	P521
)

var (
	oidDHPublicNumber = asn1.ObjectIdentifier{1, 2, 840, 10046, 2, 1}
	oidECPublicKey    = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidP256           = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidP384           = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidP521           = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

// RFC 3526's primes; the generator is 2.
var (
	modp2048, _ = new(big.Int).SetString(""+
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"+
		"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"+
		"4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"+
		"98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"+
		"9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"+
		"3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
	modp4096, _ = new(big.Int).SetString(""+
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"+
		"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"+
		"4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"+
		"98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"+
		"9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"+
		"3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"+
		"A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"+
		"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"+
		"D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"+
		"08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"+
		"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8"+
		"DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"+
		"233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"+
		"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF", 16)
)

// ErrPeerValue is the KDC's DH public value out of range, out of the
// subgroup, or not a point of the curve.
var ErrPeerValue = errors.New("pkinit: the KDC's DH public value is not usable")

// GroupNamed is the group of a pkinit_dh_min_bits value, as MIT reads it:
// 1024 (no such group here) and anything unknown are 2048, MIT's default.
func GroupNamed(s string) Group {
	switch s {
	case "P-256", "p-256":
		return P256
	case "4096":
		return MODP4096
	case "P-384", "p-384":
		return P384
	case "P-521", "p-521":
		return P521
	}

	return MODP2048
}

func (g Group) isEC() bool {
	return g == P256 || g == P384 || g == P521
}

func (g Group) curve() ecdh.Curve {
	switch g {
	case P384:
		return ecdh.P384()
	case P521:
		return ecdh.P521()
	}

	return ecdh.P256()
}

func (g Group) prime() *big.Int {
	if g == MODP4096 {
		return modp4096
	}

	return modp2048
}

// String is MIT's name of the group.
func (g Group) String() string {
	switch g {
	case MODP2048:
		return "2048"
	case P256:
		return "P-256"
	case MODP4096:
		return "4096"
	case P384:
		return "P-384"
	case P521:
		return "P-521"
	}

	return fmt.Sprintf("group %d", int(g))
}

// A DHKey is one of our key pairs: the group, the private value and the
// SubjectPublicKeyInfo carrying the public one.
type DHKey struct {
	Group Group
	SPKI  []byte

	ec *ecdh.PrivateKey
	x  *big.Int
}

type dhParams struct {
	P, G, Q *big.Int
}

type spki struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// NewDHKey is a new key pair in the group. A MODP secret exponent has
// twice the group's strength in bits (RFC 7919 5.2) and math/big's modular
// exponentiation, which is not constant time (the key is used once); the
// elliptic groups are crypto/ecdh's, which is.
func NewDHKey(g Group) (*DHKey, error) {
	if g.isEC() {
		k, err := g.curve().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		b, err := x509.MarshalPKIXPublicKey(k.PublicKey())
		if err != nil {
			return nil, err
		}

		return &DHKey{Group: g, SPKI: b, ec: k}, nil
	}

	p := g.prime()

	n := 32
	if g == MODP4096 {
		n = 64
	}

	xb := make([]byte, n)
	if _, err := rand.Read(xb); err != nil {
		return nil, err
	}

	xb[0] |= 0x80
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).Exp(big.NewInt(2), x, p)

	params, err := asn1.Marshal(dhParams{P: p, G: big.NewInt(2), Q: new(big.Int).Rsh(p, 1)})
	if err != nil {
		return nil, err
	}

	yDER, err := asn1.Marshal(y)
	if err != nil {
		return nil, err
	}

	b, err := asn1.Marshal(spki{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidDHPublicNumber, Parameters: asn1.RawValue{FullBytes: params}},
		PublicKey: asn1.BitString{Bytes: yDER, BitLength: 8 * len(yDER)},
	})
	if err != nil {
		return nil, err
	}

	return &DHKey{Group: g, SPKI: b, x: x}, nil
}

// Shared is the shared secret with the KDC's public value (the content of
// KDCDHKeyInfo's subjectPublicKey: a DER INTEGER for MODP, a point for
// EC): MODP's padded to the prime's length, EC's the x-coordinate. A MODP
// value must be in [2, p-2] and in the subgroup of order q (SP 800-56A's
// full check); an EC point on the curve.
func (k *DHKey) Shared(kdcValue []byte) ([]byte, error) {
	if k.ec != nil {
		pub, err := k.Group.curve().NewPublicKey(kdcValue)
		if err != nil {
			return nil, ErrPeerValue
		}

		z, err := k.ec.ECDH(pub)
		if err != nil {
			return nil, ErrPeerValue
		}

		return z, nil
	}

	var y *big.Int
	if rest, err := asn1.Unmarshal(kdcValue, &y); err != nil || len(rest) > 0 {
		return nil, ErrPeerValue
	}

	p := k.Group.prime()
	pm1 := new(big.Int).Sub(p, big.NewInt(1))

	if y.Cmp(big.NewInt(1)) <= 0 || y.Cmp(pm1) >= 0 {
		return nil, ErrPeerValue
	}

	if new(big.Int).Exp(y, new(big.Int).Rsh(p, 1), p).Cmp(big.NewInt(1)) != 0 {
		return nil, ErrPeerValue
	}

	z := new(big.Int).Exp(y, k.x, p)

	return z.FillBytes(make([]byte, (p.BitLen()+7)/8)), nil
}

// groupOf is the group a TD-DH-PARAMETERS AlgorithmIdentifier names, or 0.
func groupOf(a pkix.AlgorithmIdentifier) Group {
	if a.Algorithm.Equal(oidECPublicKey) {
		var c asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(a.Parameters.FullBytes, &c); err != nil {
			return 0
		}

		switch {
		case c.Equal(oidP256):
			return P256
		case c.Equal(oidP384):
			return P384
		case c.Equal(oidP521):
			return P521
		}

		return 0
	}

	if !a.Algorithm.Equal(oidDHPublicNumber) {
		return 0
	}

	// DomainParameters: p, g, q (and more, optional).
	var dp struct {
		P, G *big.Int
		Rest asn1.RawValue `asn1:"optional"`
	}

	if _, err := asn1.Unmarshal(a.Parameters.FullBytes, &dp); err != nil || dp.G.Cmp(big.NewInt(2)) != 0 {
		return 0
	}

	for _, g := range []Group{MODP2048, MODP4096} {
		if dp.P.Cmp(g.prime()) == 0 {
			return g
		}
	}

	return 0
}

// PickGroup is the first group of a TD-DH-PARAMETERS list (the KDC's
// preference, a SEQUENCE OF AlgorithmIdentifier) that is at least min, or
// 0.
func PickGroup(td []byte, min Group) Group {
	var algs []pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(td, &algs); err != nil {
		return 0
	}

	for _, a := range algs {
		if g := groupOf(a); g != 0 && g >= min {
			return g
		}
	}

	return 0
}

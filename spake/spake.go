// Package spake is SPAKE pre-authentication
// (draft-ietf-kitten-krb-spake-preauth, MIT 1.17 and later), the client's
// side, with the second factor SF-NONE. The password never leaves the
// client in a form that can be guessed at offline: where encrypted
// timestamp sends something encrypted in the password's key, SPAKE runs a
// key exchange masked by it.
//
// The exchange. The KDC offers PA-SPAKE (empty) in its PREAUTH_REQUIRED
// error; the client sends the groups it takes (support); the KDC picks one
// and answers MORE_PREAUTH_DATA_REQUIRED with its public key
// T = x*G + w*M (challenge), or sends that challenge at once
// (optimistically) in place of the empty offer. The client's public key is
// S = y*G + w*N and the shared element K = y*(T - w*M), which the KDC
// finds as x*(S - w*N). The client's response carries S and SF-NONE
// encrypted in K'[1]; the reply key becomes K'[0].
//
// w is PRF+(initial reply key, "SPAKEsecret" || group) as a scalar. The
// transcript hash starts at zeros and takes H(hash || support ||
// challenge), then H(hash || S); a challenge the client refuses (a group it
// does not take) is not in it. K'[n] is KRB-FX-CF2(initial key, "SPAKE",
// random-to-key(H("SPAKEkey" || group || etype || w's bytes || K || hash ||
// KDC-REQ-BODY || n || block)), "keyderiv"), the body the one inside FAST
// when armored.
//
// The groups: edwards25519 (SHA-256), P-256 (SHA-256), P-384 (SHA-384) and
// P-521 (SHA-512). P-521's multiplier is 66 bytes, as MIT's iana.c and the
// draft's own test vectors have it; the draft's registry table says 48.
// Private scalars are multiples of the cofactor (8 for edwards25519). Every
// multiplication by w, x or y runs in constant time (filippo.io/edwards25519
// and filippo.io/nistec, the code of Go's crypto/internal, exported).
package spake

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"

	"filippo.io/edwards25519"
	"filippo.io/nistec"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/types"
)

// The groups' numbers (the draft's IANA registry).
const (
	Edwards25519 int32 = 1
	P256         int32 = 2
	P384         int32 = 3
	P521         int32 = 4
)

// SFNone is the second factor "none".
const SFNone int32 = 1

// ErrPeerKey is a public key that is not a point of the group, or a shared
// element that is the identity.
var ErrPeerKey = errors.New("spake: the peer's public key is not usable")

// A Group is one of the SPAKE groups.
type Group struct {
	ID int32
	// MultLen is the length of a multiplier (w, x, y); ElemLen of an
	// encoded element.
	MultLen, ElemLen int
	newHash          func() hash.Hash
	m, n             []byte
	ops              groupOps
}

// groupOps is a curve's arithmetic on encoded elements and scalars (little
// endian for edwards25519, big-endian for the NIST curves).
type groupOps interface {
	// mulAdd is a*G + b*P, encoded; b is w's bytes (reduced or not).
	mulAdd(a, b, p []byte) ([]byte, error)
	// shared is a*(peer - b*P), encoded; ErrPeerKey for a peer that is not
	// a point or a result that is the identity.
	shared(a, b, p, peer []byte) ([]byte, error)
	// private is a new private scalar, a multiple of the cofactor.
	private() ([]byte, error)
	// reduce is w as the group's scalar (mod its order), encoded.
	reduce(w []byte) []byte
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}

	return b
}

var groups = map[int32]*Group{
	Edwards25519: {ID: Edwards25519, MultLen: 32, ElemLen: 32, newHash: sha256.New,
		m:   mustHex("d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf"),
		n:   mustHex("d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab"),
		ops: edOps{}},
	P256: {ID: P256, MultLen: 32, ElemLen: 33, newHash: sha256.New,
		m:   mustHex("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"),
		n:   mustHex("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"),
		ops: nistOps[*nistec.P256Point]{newPoint: nistec.NewP256Point, order: p256Order}},
	P384: {ID: P384, MultLen: 48, ElemLen: 49, newHash: sha512.New384,
		m:   mustHex("030ff0895ae5ebf6187080a82d82b42e2765e3b2f8749c7e05eba366434b363d3dc36f15314739074d2eb8613fceec2853"),
		n:   mustHex("02c72cf2e390853a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543bb252c5490214cf9aa3f0baab4b665c10"),
		ops: nistOps[*nistec.P384Point]{newPoint: nistec.NewP384Point, order: p384Order}},
	P521: {ID: P521, MultLen: 66, ElemLen: 67, newHash: sha512.New,
		m:   mustHex("02003f06f38131b2ba2600791e82488e8d20ab889af753a41806c5db18d37d85608cfae06b82e4a72cd744c719193562a653ea1f119eef9356907edc9b56979962d7aa"),
		n:   mustHex("0200c7924b9ec017f3094562894336a53c50167ba8c5963876880542bc669e494b2532d76c5b53dfb349fdf69154b9e0048c58a42e8ed04cef052a3bc349d95575cd25"),
		ops: nistOps[*nistec.P521Point]{newPoint: nistec.NewP521Point, order: p521Order}},
}

// GroupByID is the group numbered id; false for one this package does not
// have.
func GroupByID(id int32) (*Group, bool) {
	g, ok := groups[id]
	return g, ok
}

// GroupsNamed are the groups a list names (MIT's spake_preauth_groups:
// "edwards25519 P-256 ..."; spaces or commas between, case ignored), in its
// order, each once; unknown names are skipped, as MIT does.
func GroupsNamed(list string) []int32 {
	var out []int32

	for _, f := range strings.FieldsFunc(list, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' }) {
		var id int32

		switch strings.ToLower(f) {
		case "edwards25519":
			id = Edwards25519
		case "p-256":
			id = P256
		case "p-384":
			id = P384
		case "p-521":
			id = P521
		default:
			continue
		}

		dup := false

		for _, o := range out {
			dup = dup || o == id
		}

		if !dup {
			out = append(out, id)
		}
	}

	return out
}

func (g *Group) hash(parts ...[]byte) []byte {
	h := g.newHash()
	for _, p := range parts {
		h.Write(p)
	}

	return h.Sum(nil)
}

func be32(v int32) []byte {
	return binary.BigEndian.AppendUint32(nil, uint32(v))
}

// WBytes is w's bytes: PRF+(key, "SPAKEsecret" || group), the
// multiplier's length.
func (g *Group) WBytes(key types.EncryptionKey) ([]byte, error) {
	return crypto.PRFPlus(key, append([]byte("SPAKEsecret"), be32(g.ID)...), g.MultLen)
}

// ReducedW is w as the group's scalar, reduced mod its order (little
// endian on edwards25519, big-endian on the others).
func (g *Group) ReducedW(wbytes []byte) []byte {
	return g.ops.reduce(wbytes)
}

// Private is a new private scalar, uniform below the group's order times
// its cofactor and a multiple of the cofactor.
func (g *Group) Private() ([]byte, error) {
	return g.ops.private()
}

// Public is the public key priv*G + w*M (the KDC's T, useM) or priv*G + w*N
// (the client's S).
func (g *Group) Public(priv, wbytes []byte, useM bool) ([]byte, error) {
	p := g.n
	if useM {
		p = g.m
	}

	return g.ops.mulAdd(priv, wbytes, p)
}

// Shared is the shared element K = priv*(peer - w*M) (the client's, useM,
// with the KDC's T) or priv*(peer - w*N) (the KDC's).
func (g *Group) Shared(priv, wbytes, peer []byte, useM bool) ([]byte, error) {
	if len(peer) != g.ElemLen {
		return nil, ErrPeerKey
	}

	p := g.n
	if useM {
		p = g.m
	}

	return g.ops.shared(priv, wbytes, p, peer)
}

// Transcript is the transcript hash updated with a || b; an empty one
// starts at zeros.
func (g *Group) Transcript(thash, a, b []byte) []byte {
	if len(thash) == 0 {
		thash = make([]byte, g.newHash().Size())
	}

	return g.hash(thash, a, b)
}

// Key is K'[n], of the initial key's type: KRB-FX-CF2(ikey, "SPAKE",
// random-to-key(H("SPAKEkey" || group || etype || w || K || thash || body
// || n || block) || ...), "keyderiv").
func (g *Group) Key(ikey types.EncryptionKey, wbytes, k, thash, body []byte, n int32) (types.EncryptionKey, error) {
	e, err := crypto.GetEtype(ikey.KeyType)
	if err != nil {
		return types.EncryptionKey{}, err
	}

	prefix := append(append(append([]byte("SPAKEkey"), be32(g.ID)...), be32(ikey.KeyType)...), wbytes...)
	prefix = append(append(append(append(prefix, k...), thash...), body...), be32(n)...)

	want := e.GetKeySeedBitLength() / 8

	var seed []byte
	for counter := byte(1); len(seed) < want; counter++ {
		seed = append(seed, g.hash(prefix, []byte{counter})...)
	}

	hk, err := crypto.RandomToKey(ikey.KeyType, seed[:want])
	if err != nil {
		return hk, err
	}

	return crypto.CF2(ikey, "SPAKE", hk, "keyderiv")
}

// --- edwards25519 ----------------------------------------------------------

type edOps struct{}

// edScalar is s (32 bytes, little-endian, reduced or not) as a canonical
// scalar: s mod L.
func edScalar(s []byte) *edwards25519.Scalar {
	wide := make([]byte, 64)
	copy(wide, s)

	x, err := edwards25519.NewScalar().SetUniformBytes(wide)
	if err != nil {
		panic(err) // 64 bytes are always taken
	}

	return x
}

// edMul is s*P exactly, for any 32-byte little-endian s: with s = 8q + r,
// q*(8P) + r*P (8P is in the prime-order subgroup, so q may be reduced mod
// L; r < 8 is a canonical scalar). A private scalar (a multiple of 8) works
// on a peer point with a small-order component as the draft wants.
func edMul(s []byte, p *edwards25519.Point) *edwards25519.Point {
	var q [32]byte

	for i := 0; i < 32; i++ {
		q[i] = s[i] >> 3
		if i < 31 {
			q[i] |= s[i+1] << 5
		}
	}

	r := make([]byte, 32)
	r[0] = s[0] & 7

	rs, err := edwards25519.NewScalar().SetCanonicalBytes(r)
	if err != nil {
		panic(err)
	}

	p8 := new(edwards25519.Point).MultByCofactor(p)
	a := new(edwards25519.Point).ScalarMult(edScalar(q[:]), p8)
	b := new(edwards25519.Point).ScalarMult(rs, p)

	return a.Add(a, b)
}

func (edOps) mulAdd(a, b, p []byte) ([]byte, error) {
	pp, err := new(edwards25519.Point).SetBytes(p)
	if err != nil || len(a) != 32 {
		return nil, ErrPeerKey
	}

	x := edMul(a, edwards25519.NewGeneratorPoint())
	y := new(edwards25519.Point).ScalarMult(edScalar(b), pp)

	return x.Add(x, y).Bytes(), nil
}

func (edOps) shared(a, b, p, peer []byte) ([]byte, error) {
	pp, err := new(edwards25519.Point).SetBytes(p)
	if err != nil || len(a) != 32 {
		return nil, ErrPeerKey
	}

	q, err := new(edwards25519.Point).SetBytes(peer)
	if err != nil {
		return nil, ErrPeerKey
	}

	wp := new(edwards25519.Point).ScalarMult(edScalar(b), pp)
	k := edMul(a, q.Subtract(q, wp))

	if k.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil, ErrPeerKey
	}

	return k.Bytes(), nil
}

// private is 8 times a scalar reduced from 64 random bytes, as a 256-bit
// little-endian number (below 8L < 2^256).
func (edOps) private() ([]byte, error) {
	r := make([]byte, 64)
	if _, err := rand.Read(r); err != nil {
		return nil, err
	}

	s := edScalar(r).Bytes()

	var carry byte

	for i := range s {
		next := s[i] >> 5
		s[i] = s[i]<<3 | carry
		carry = next
	}

	return s, nil
}

func (edOps) reduce(w []byte) []byte {
	return edScalar(w).Bytes()
}

// --- P-256, P-384, P-521 ---------------------------------------------------

// nistPoint is what this package uses of a nistec point.
type nistPoint[P any] interface {
	SetGenerator() P
	SetBytes([]byte) (P, error)
	Add(P, P) P
	ScalarMult(P, []byte) (P, error)
	ScalarBaseMult([]byte) (P, error)
	BytesCompressed() []byte
}

type nistOps[P nistPoint[P]] struct {
	newPoint func() P
	order    *big.Int
}

// The groups' orders.
var (
	p256Order = elliptic.P256().Params().N
	p384Order = elliptic.P384().Params().N
	p521Order = elliptic.P521().Params().N
)

func (o nistOps[P]) scalarLen() int {
	return (o.order.BitLen() + 7) / 8
}

func (o nistOps[P]) mulAdd(a, b, p []byte) ([]byte, error) {
	if len(a) != o.scalarLen() || len(b) != o.scalarLen() {
		return nil, ErrPeerKey
	}


	pp, err := o.newPoint().SetBytes(p)
	if err != nil {
		return nil, ErrPeerKey
	}

	x, err := o.newPoint().ScalarBaseMult(a)
	if err != nil {
		return nil, err
	}

	y, err := o.newPoint().ScalarMult(pp, b)
	if err != nil {
		return nil, err
	}

	return o.newPoint().Add(x, y).BytesCompressed(), nil
}

// negated is -P for a compressed P: the other y, by the parity byte.
func negated(enc []byte) []byte {
	out := append([]byte(nil), enc...)
	if len(out) > 1 {
		out[0] ^= 1 // 02 <-> 03
	}

	return out
}

func (o nistOps[P]) shared(a, b, p, peer []byte) ([]byte, error) {
	if len(a) != o.scalarLen() || len(b) != o.scalarLen() || (peer[0] != 2 && peer[0] != 3) {
		return nil, ErrPeerKey
	}


	pp, err := o.newPoint().SetBytes(p)
	if err != nil {
		return nil, ErrPeerKey
	}

	q, err := o.newPoint().SetBytes(peer)
	if err != nil {
		return nil, ErrPeerKey
	}

	wp, err := o.newPoint().ScalarMult(pp, b)
	if err != nil {
		return nil, err
	}

	d := q
	if enc := wp.BytesCompressed(); len(enc) > 1 {
		nw, err := o.newPoint().SetBytes(negated(enc))
		if err != nil {
			return nil, err
		}

		d = o.newPoint().Add(q, nw)
	}

	k, err := o.newPoint().ScalarMult(d, a)
	if err != nil {
		return nil, err
	}

	enc := k.BytesCompressed()
	if len(enc) == 1 {
		return nil, ErrPeerKey // the identity
	}

	return enc, nil
}

// private is uniform in [1, n-1] (the cofactor is 1).
func (o nistOps[P]) private() ([]byte, error) {
	for {
		k, err := rand.Int(rand.Reader, o.order)
		if err != nil {
			return nil, err
		}

		if k.Sign() > 0 {
			return k.FillBytes(make([]byte, o.scalarLen())), nil
		}
	}
}

// reduce is w mod n; for the tests (the exchange multiplies by w's bytes
// as they are, which gives the same point).
func (o nistOps[P]) reduce(w []byte) []byte {
	return new(big.Int).Mod(new(big.Int).SetBytes(w), o.order).FillBytes(make([]byte, o.scalarLen()))
}

// String is the group's name (MIT's).
func (g *Group) String() string {
	switch g.ID {
	case Edwards25519:
		return "edwards25519"
	case P256:
		return "P-256"
	case P384:
		return "P-384"
	case P521:
		return "P-521"
	}

	return fmt.Sprintf("group %d", g.ID)
}

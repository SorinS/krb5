package spake

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"

	"filippo.io/edwards25519"
	"filippo.io/nistec"
	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/types"
)

// testdata/vectors.txt is Appendix C of draft-ietf-kitten-krb-spake-preauth
// (made by gslib.git's krb5/scripts/spake_vectors.py from the draft's
// text), one vector per line:
// name|etype|group|key|w|w_reduced|x|y|X|Y|T|S|K|support|optimistic|challenge|thash1|thash2|body|K0|K1|K2|K3.
func TestVectors(t *testing.T) {
	t.Parallel()

	f, err := os.Open("testdata/vectors.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	h := func(s string) []byte {
		if s == "-" {
			return nil
		}

		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}

		return b
	}

	var n int

	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)

	for sc.Scan() {
		w := strings.Split(sc.Text(), "|")
		if len(w) != 23 {
			continue
		}

		gid, _ := strconv.Atoi(w[2])
		if gid == -1 {
			// The draft's edwards25519 with SHA-1, numbered -1: its K' is
			// not reproducible (MIT's t_vectors.c leaves it out too).
			continue
		}

		et, _ := strconv.Atoi(w[1])
		name := w[0]
		g, ok := GroupByID(int32(gid))

		if !ok {
			t.Fatalf("%s: group %d", name, gid)
		}

		key := types.EncryptionKey{KeyType: int32(et), KeyValue: h(w[3])}

		wb, err := g.WBytes(key)
		if err != nil || !bytes.Equal(wb, h(w[4])) {
			t.Fatalf("%s: w %x, %v", name, wb, err)
		}

		if got := g.ReducedW(wb); !bytes.Equal(got, h(w[5])) {
			t.Errorf("%s: w reduced %x", name, got)
		}

		x, y := h(w[6]), h(w[7])

		T, err := g.Public(x, wb, true)
		if err != nil || !bytes.Equal(T, h(w[10])) {
			t.Errorf("%s: T %x, %v", name, T, err)
		}

		S, err := g.Public(y, wb, false)
		if err != nil || !bytes.Equal(S, h(w[11])) {
			t.Errorf("%s: S %x, %v", name, S, err)
		}

		kc, err := g.Shared(y, wb, T, true)
		if err != nil || !bytes.Equal(kc, h(w[12])) {
			t.Errorf("%s: client's K %x, %v", name, kc, err)
		}

		kk, err := g.Shared(x, wb, S, false)
		if err != nil || !bytes.Equal(kk, h(w[12])) {
			t.Errorf("%s: KDC's K %x, %v", name, kk, err)
		}

		// The messages as the draft encodes them.
		support := h(w[13])
		if support != nil {
			var m Message
			if err := m.Unmarshal(support); err != nil || m.Choice != ChoiceSupport {
				t.Errorf("%s: support %+v, %v", name, m, err)
			}

			again, _ := m.Marshal()
			if !bytes.Equal(again, support) {
				t.Errorf("%s: support re-encoded %x", name, again)
			}
		}

		ch := h(w[15])
		cm := Message{Choice: ChoiceChallenge, Group: int32(gid), PubKey: T, Factors: []SecondFactor{{Type: SFNone}}}

		if b, _ := cm.Marshal(); !bytes.Equal(b, ch) {
			t.Errorf("%s: challenge %x", name, b)
		}

		th1 := g.Transcript(nil, support, ch)
		if !bytes.Equal(th1, h(w[16])) {
			t.Errorf("%s: transcript after challenge %x", name, th1)
		}

		th2 := g.Transcript(th1, S, nil)
		if !bytes.Equal(th2, h(w[17])) {
			t.Errorf("%s: final transcript %x", name, th2)
		}

		body := h(w[18])
		for i := 0; i < 4; i++ {
			k, err := g.Key(key, wb, kc, th2, body, int32(i))
			if err != nil || k.KeyType != key.KeyType || !bytes.Equal(k.KeyValue, h(w[19+i])) {
				t.Errorf("%s: K'[%d] %x, %v", name, i, k.KeyValue, err)
			}
		}

		// The client: its support message (when the vector has one), the
		// challenge, its response with S, SF-NONE in K'[1], K'[0].
		c := NewClient([]int32{Edwards25519, P256, P384, P521})
		if support != nil {
			c.Groups = nil

			var m Message
			_ = m.Unmarshal(support)
			c.Groups = m.Groups

			if b, _ := c.Support(); !bytes.Equal(b, support) {
				t.Errorf("%s: client's support %x", name, b)
			}
		}

		if err := c.Challenge(ch, key, y); err != nil {
			t.Fatalf("%s: challenge: %v", name, err)
		}

		resp, k0, err := c.Response(body)
		if err != nil || !bytes.Equal(k0.KeyValue, h(w[19])) {
			t.Fatalf("%s: response K'[0] %x, %v", name, k0.KeyValue, err)
		}

		var rm Message
		if err := rm.Unmarshal(resp); err != nil || rm.Choice != ChoiceResponse || !bytes.Equal(rm.PubKey, S) {
			t.Fatalf("%s: response %+v, %v", name, rm, err)
		}

		k1 := types.EncryptionKey{KeyType: key.KeyType, KeyValue: h(w[20])}

		plain, err := crypto.DecryptEncPart(rm.Enc, k1, keyusage.KEY_USAGE_SPAKE)
		if err != nil {
			t.Fatalf("%s: factor: %v", name, err)
		}

		var sf SecondFactor

		var rv asn1.RawValue
		rest, _ := asn1.Unmarshal(plain, &rv)

		if _, err := asn1.Unmarshal(plain[:len(plain)-len(rest)], &sf); err != nil || sf.Type != SFNone || sf.Data != nil {
			t.Errorf("%s: factor %+v, %v", name, sf, err)
		}

		// An optimistic challenge in a group the client does not take is
		// refused.
		if opt := h(w[14]); opt != nil {
			var om Message
			if err := om.Unmarshal(opt); err != nil {
				t.Errorf("%s: optimistic %v", name, err)
			}

			c := NewClient([]int32{P521 + 1})
			if c.Challenge(opt, key, y) == nil {
				t.Errorf("%s: a challenge in a group not taken", name)
			}
		}

		n++
	}

	if n < 8 {
		t.Errorf("%d vectors", n)
	}
}

// Public keys that are not usable: not points, the wrong length, the
// identity (K would be predictable).
func TestBadPeerKeys(t *testing.T) {
	t.Parallel()

	key := types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)}

	for _, id := range []int32{Edwards25519, P256, P384, P521} {
		g, _ := GroupByID(id)

		wb, err := g.WBytes(key)
		if err != nil {
			t.Fatal(err)
		}

		y, err := g.Private()
		if err != nil {
			t.Fatal(err)
		}

		// w*M: then T - w*M is the identity.
		wm, err := g.Public(make([]byte, g.MultLen), wb, true)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := g.Shared(y, wb, wm, true); err == nil {
			t.Errorf("%s: K the identity", g)
		}

		if _, err := g.Shared(y, wb, wm[:len(wm)-1], true); err == nil {
			t.Errorf("%s: a short key", g)
		}

		if _, err := g.Shared(y, wb, append(wm, 0), true); err == nil {
			t.Errorf("%s: a long key", g)
		}

		// An x (or y) with no point on the curve.
		var bad []byte

		for i := 2; i < 256 && bad == nil; i++ {
			b := make([]byte, g.ElemLen)
			if id == Edwards25519 {
				b[0] = byte(i)
				if _, err := new(edwards25519.Point).SetBytes(b); err != nil {
					bad = b
				}
			} else {
				b[0], b[len(b)-1] = 2, byte(i)
				if !nistDecodes(id, b) {
					bad = b
				}
			}
		}

		if _, err := g.Shared(y, wb, bad, true); err == nil {
			t.Errorf("%s: not a point", g)
		}

		// A KDC and a client agree.
		x, _ := g.Private()
		T, _ := g.Public(x, wb, true)
		S, _ := g.Public(y, wb, false)
		kc, err1 := g.Shared(y, wb, T, true)
		kk, err2 := g.Shared(x, wb, S, false)

		if err1 != nil || err2 != nil || !bytes.Equal(kc, kk) {
			t.Errorf("%s: K %x and %x, %v %v", g, kc, kk, err1, err2)
		}
	}
}

func nistDecodes(id int32, b []byte) bool {
	var err error

	switch id {
	case P256:
		_, err = nistec.NewP256Point().SetBytes(b)
	case P384:
		_, err = nistec.NewP384Point().SetBytes(b)
	case P521:
		_, err = nistec.NewP521Point().SetBytes(b)
	}

	return err == nil
}

func TestGroupsNamed(t *testing.T) {
	t.Parallel()

	got := GroupsNamed("P-256, edwards25519 nonsense p-521 P-256")
	if len(got) != 3 || got[0] != P256 || got[1] != Edwards25519 || got[2] != P521 {
		t.Errorf("%v", got)
	}
}

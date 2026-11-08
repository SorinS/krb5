package pkinit

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/SorinS/krb5/iana/errorcode"
	"github.com/SorinS/krb5/iana/nametype"
	"github.com/SorinS/krb5/types"
)

// testdata/kdc.txt: a CA, KDC certificates and their keys made by OpenSSL
// (test/mitkdc/pki.py):
// "now UNIX" (a time inside their validity), "cert NAME HEX" (DER) and
// "key NAME HEX" (PKCS #8) for ca, kdc, kdc-dns, kdc-noeku and rogue.
type vectors struct {
	now   time.Time
	certs map[string]*x509.Certificate
	keys  map[string]crypto.Signer
}

func loadVectors(t *testing.T) *vectors {
	t.Helper()

	f, err := os.Open("testdata/kdc.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	v := &vectors{certs: map[string]*x509.Certificate{}, keys: map[string]crypto.Signer{}}
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)

	for sc.Scan() {
		w := strings.Fields(sc.Text())

		switch {
		case len(w) == 2 && w[0] == "now":
			n, _ := strconv.ParseInt(w[1], 10, 64)
			v.now = time.Unix(n, 0)
		case len(w) == 3 && w[0] == "cert":
			b, _ := hex.DecodeString(w[2])

			c, err := x509.ParseCertificate(b)
			if err != nil {
				t.Fatal(err)
			}

			v.certs[w[1]] = c
		case len(w) == 3 && w[0] == "key":
			b, _ := hex.DecodeString(w[2])

			k, err := x509.ParsePKCS8PrivateKey(b)
			if err != nil {
				t.Fatal(err)
			}

			v.keys[w[1]] = k.(crypto.Signer)
		}
	}

	return v
}

func (v *vectors) trust(anchor string, hosts []string, eku EKUCheck) *Trust {
	p := x509.NewCertPool()
	p.AddCert(v.certs[anchor])

	return &Trust{Anchors: p, KDCHostnames: hosts, EKU: eku}
}

// kdcReply is the PA-PK-AS-REP a KDC with the signer's certificate and key
// would send for the client's DH key: its own key pair in the group, the
// KDCDHKeyInfo with the nonce, signed, and the KDF (KDFOld: none named).
// It returns the reply's value and the shared secret.
func kdcReply(t *testing.T, v *vectors, signer string, client *DHKey, nonce int64, kdf KDF) ([]byte, []byte) {
	t.Helper()

	var kdcValue, z []byte

	if client.Group.isEC() {
		k, err := client.Group.curve().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		pub, err := x509.ParsePKIXPublicKey(client.SPKI)
		if err != nil {
			t.Fatal(err)
		}

		cp, err := pub.(*ecdsa.PublicKey).ECDH()
		if err != nil {
			t.Fatal(err)
		}

		if z, err = k.ECDH(cp); err != nil {
			t.Fatal(err)
		}

		kdcValue = k.PublicKey().Bytes()
	} else {
		p := client.Group.prime()
		x, _ := rand.Int(rand.Reader, new(big.Int).Rsh(p, 1))
		y := new(big.Int).Exp(big.NewInt(2), x, p)
		kdcValue, _ = asn1.Marshal(y)

		var s spki
		if _, err := asn1.Unmarshal(client.SPKI, &s); err != nil {
			t.Fatal(err)
		}

		var cy *big.Int
		if _, err := asn1.Unmarshal(s.PublicKey.Bytes, &cy); err != nil {
			t.Fatal(err)
		}

		z = new(big.Int).Exp(cy, x, p).FillBytes(make([]byte, (p.BitLen()+7)/8))
	}

	info, err := asn1.Marshal(kdcDHKeyInfo{SubjectPublicKey: asn1.BitString{Bytes: kdcValue, BitLength: 8 * len(kdcValue)}, Nonce: nonce})
	if err != nil {
		t.Fatal(err)
	}

	sd, err := Sign(oidPKINITDHKeyData, info, v.keys[signer], v.certs[signer], nil)
	if err != nil {
		t.Fatal(err)
	}

	parts := [][]byte{implicit(0, sd)}

	if kdf != KDFOld {
		o, _ := asn1.Marshal(kdf.oid())
		parts = append(parts, explicit(2, sequence(explicit(0, o))))
	}

	return explicit(0, sequence(parts...)), z
}

// The client's side of a KDC's reply: the reply key in every group by
// each KDF and by octetstring2key; refused for a wrong nonce, a KDF not
// offered, a signer not trusted or not naming the KDC, an EKU missing.
func TestReplyKey(t *testing.T) {
	t.Parallel()

	v := loadVectors(t)
	client := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "pat")
	server := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/P.TEST")
	asReq := []byte("the AS-REQ as sent")
	trust := v.trust("ca", nil, EKUKDC)

	for _, g := range []Group{MODP2048, P256, MODP4096, P384, P521} {
		dh, err := NewDHKey(g)
		if err != nil {
			t.Fatal(err)
		}

		r := &Request{DH: dh, Nonce: 0x7abcdef0, KDFs: DefaultKDFs}

		for _, kdf := range []KDF{KDFOld, KDFSHA1, KDFSHA256, KDFSHA384, KDFSHA512} {
			rep, z := kdcReply(t, v, "kdc", dh, 0x7abcdef0, kdf)

			got, err := r.ReplyKey(rep, trust, 18, client, "P.TEST", server, "P.TEST", asReq, v.now)
			if err != nil {
				t.Fatalf("%v, KDF %d: %v", g, kdf, err)
			}

			var want types.EncryptionKey
			if kdf == KDFOld {
				want, _ = OctetString2Key(18, z)
			} else {
				oi, _ := OtherInfo(kdf, client, "P.TEST", server, "P.TEST", 18, asReq, rep)
				want, _ = DeriveKey(kdf, 18, z, oi)
			}

			if !bytes.Equal(got.KeyValue, want.KeyValue) {
				t.Errorf("%v, KDF %d: the reply key is not the KDC's", g, kdf)
			}
		}
	}

	dh, _ := NewDHKey(P256)
	r := &Request{DH: dh, Nonce: 5, KDFs: []KDF{KDFSHA256}}

	refused := func(what string, rep []byte, tr *Trust, code int32) {
		t.Helper()

		_, err := r.ReplyKey(rep, tr, 18, client, "P.TEST", server, "P.TEST", asReq, v.now)

		var pe *Error
		if err == nil || (code != 0 && (!errors.As(err, &pe) || pe.Code != code)) {
			t.Errorf("%s: %v", what, err)
		}
	}

	rep, _ := kdcReply(t, v, "kdc", dh, 6, KDFSHA256)
	refused("another nonce", rep, trust, 0)

	rep, _ = kdcReply(t, v, "kdc", dh, 5, KDFSHA512)
	refused("a KDF not offered", rep, trust, errorcode.KDC_ERR_NO_ACCEPTABLE_KDF)

	rep, _ = kdcReply(t, v, "rogue", dh, 5, KDFSHA256)
	refused("a signer from another CA", rep, trust, errorcode.KDC_ERROR_KDC_NOT_TRUSTED)

	rep, _ = kdcReply(t, v, "kdc", dh, 5, KDFSHA256)
	refused("our anchor another CA", rep, v.trust("rogue", nil, EKUKDC), errorcode.KDC_ERROR_KDC_NOT_TRUSTED)

	// kdc-dns: named by host name only, with the KDC EKU.
	rep, _ = kdcReply(t, v, "kdc-dns", dh, 5, KDFSHA256)
	refused("a KDC by host name not taken", rep, trust, errorcode.KDC_ERR_KDC_NAME_MISMATCH)

	if _, err := r.ReplyKey(rep, v.trust("ca", []string{"KDC.R.TEST"}, EKUKDC), 18, client, "P.TEST", server, "P.TEST", asReq, v.now); err != nil {
		t.Errorf("a KDC by host name taken: %v", err)
	}

	refused("a KDC by host name without serverAuth", rep, v.trust("ca", []string{"kdc.r.test"}, EKUServerAuth), errorcode.KDC_ERR_INCONSISTENT_KEY_PURPOSE)

	// kdc-noeku: N.TEST's id-pkinit-san (not P.TEST's), EKU serverAuth.
	rep, _ = kdcReply(t, v, "kdc-noeku", dh, 5, KDFSHA256)
	refused("another realm's KDC", rep, trust, errorcode.KDC_ERR_KDC_NAME_MISMATCH)

	if _, err := r.ReplyKey(rep, trust, 18, client, "N.TEST", server, "N.TEST", asReq, v.now); err != nil {
		t.Errorf("its own realm, by its SAN (the EKU not checked, as MIT): %v", err)
	}

	// A signature that does not check: the content changed.
	rep, _ = kdcReply(t, v, "kdc", dh, 5, KDFSHA256)
	tampered := append([]byte(nil), rep...)
	tampered[len(tampered)/3] ^= 1
	refused("a reply tampered with", tampered, trust, 0)
}

// MODP values out of range or out of the subgroup are refused.
func TestDHValues(t *testing.T) {
	t.Parallel()

	k, err := NewDHKey(MODP2048)
	if err != nil {
		t.Fatal(err)
	}

	p := MODP2048.prime()
	q := new(big.Int).Rsh(p, 1)

	// A non-residue: y^q = p-1.
	var outside *big.Int

	for y := int64(3); outside == nil; y++ {
		if new(big.Int).Exp(big.NewInt(y), q, p).Cmp(big.NewInt(1)) != 0 {
			outside = big.NewInt(y)
		}
	}

	for _, y := range []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(p, big.NewInt(1)), p, outside} {
		b, _ := asn1.Marshal(y)
		if _, err := k.Shared(b); err == nil {
			t.Errorf("%v taken", y)
		}
	}

	ek, _ := NewDHKey(P256)
	if _, err := ek.Shared(make([]byte, 65)); err == nil {
		t.Error("a point not on the curve taken")
	}

	// Two of ours agree.
	a, _ := NewDHKey(P384)
	b, _ := NewDHKey(P384)
	pa, _ := x509.ParsePKIXPublicKey(a.SPKI)
	pb, _ := x509.ParsePKIXPublicKey(b.SPKI)
	ea, _ := pa.(*ecdsa.PublicKey).ECDH()
	eb, _ := pb.(*ecdsa.PublicKey).ECDH()
	za, err1 := b.Shared(ea.Bytes())
	zb, err2 := a.Shared(eb.Bytes())

	if err1 != nil || err2 != nil || !bytes.Equal(za, zb) {
		t.Errorf("P-384: %v %v", err1, err2)
	}
}

func TestPickGroup(t *testing.T) {
	t.Parallel()

	k4, _ := NewDHKey(MODP4096)
	k2, _ := NewDHKey(MODP2048)
	kp, _ := NewDHKey(P384)

	var algs []asn1.RawValue

	for _, k := range []*DHKey{k2, kp, k4} {
		var s struct {
			Algorithm asn1.RawValue
			PublicKey asn1.BitString
		}

		if _, err := asn1.Unmarshal(k.SPKI, &s); err != nil {
			t.Fatal(err)
		}

		algs = append(algs, s.Algorithm)
	}

	td, _ := asn1.Marshal(algs)

	if g := PickGroup(td, MODP2048); g != MODP2048 {
		t.Errorf("%v", g)
	}

	if g := PickGroup(td, MODP4096); g != P384 {
		t.Errorf("%v", g)
	}

	if g := PickGroup(td, P521); g != 0 {
		t.Errorf("%v", g)
	}
}

// OpenSSL as the oracle of our CMS: it verifies what we sign, and we
// verify what it signs.
func TestCMSOpenSSL(t *testing.T) {
	t.Parallel()

	ssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("no openssl")
	}

	v := loadVectors(t)
	dir := t.TempDir()
	pemFile := func(name string, der []byte, kind string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}

		return p
	}

	ca := pemFile("ca.pem", v.certs["ca"].Raw, "CERTIFICATE")
	content := []byte("an AuthPack, or anything")

	// Ours, verified by OpenSSL.
	signed, err := Sign(oidPKINITAuthData, content, v.keys["kdc"], v.certs["kdc"], nil)
	if err != nil {
		t.Fatal(err)
	}

	in := filepath.Join(dir, "ours.der")
	_ = os.WriteFile(in, signed, 0o600)

	cmd := exec.Command(ssl, "cms", "-verify", "-inform", "DER", "-in", in, "-CAfile", ca, "-purpose", "any",
		"-attime", strconv.FormatInt(v.now.Unix(), 10))

	out, err := cmd.Output()
	if err != nil || !bytes.Equal(out, content) {
		t.Errorf("openssl cms -verify: %v, %q", err, out)
	}

	// OpenSSL's, verified by us.
	keyDER, _ := x509.MarshalPKCS8PrivateKey(v.keys["kdc"])
	key := pemFile("kdc.key", keyDER, "PRIVATE KEY")
	cert := pemFile("kdc.pem", v.certs["kdc"].Raw, "CERTIFICATE")
	cfile := filepath.Join(dir, "content")
	_ = os.WriteFile(cfile, content, 0o600)

	out, err = exec.Command(ssl, "cms", "-sign", "-binary", "-nodetach", "-outform", "DER", "-econtent_type", "1.3.6.1.5.2.3.2",
		"-md", "sha256", "-signer", cert, "-inkey", key, "-in", cfile).Output()
	if err != nil {
		t.Fatalf("openssl cms -sign: %v", err)
	}

	sd, err := ParseSignedData(out)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sd.Verify(); err != nil || !bytes.Equal(sd.Content, content) || !sd.ContentType.Equal(oidPKINITDHKeyData) {
		t.Errorf("OpenSSL's SignedData: %v", err)
	}

	// Ours unsigned (anonymous) reads back.
	u, err := Unsigned(oidPKINITAuthData, content)
	if err != nil {
		t.Fatal(err)
	}

	usd, err := ParseSignedData(u)
	if err != nil || !bytes.Equal(usd.Content, content) {
		t.Errorf("unsigned: %v", err)
	}

	if _, err := usd.Verify(); err == nil {
		t.Error("an unsigned SignedData verified")
	}
}

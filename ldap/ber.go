// Package ldap is a small LDAPv3 client (RFC 4511) for what Kerberos needs
// of a directory: a SASL GSSAPI bind (RFC 4752) with its security layer, by
// gsskrb5.SASL; searches; the "Who am I?" operation (RFC 4532); and the
// Active Directory lookups a service makes with what a PAC tells it (SIDs
// to names, a user's groups by tokenGroups, the naming context).
//
// With the integrity or confidentiality layer (Active Directory requires
// signing unless the connection is TLS, if so configured), every message
// after the bind travels in a Wrap token. It reads BER as servers send it
// (long-form lengths included), and writes DER.
package ldap

import (
	"errors"
	"fmt"
)

// BER classes and the constructed bit, as in an identifier octet.
const (
	classUniversal   = 0x00
	classApplication = 0x40
	classContext     = 0x80
	constructed      = 0x20
)

var errBER = errors.New("ldap: malformed BER")

// tlv is a BER element: its identifier octet (tags below 31 only, which is
// all LDAP has) and contents.
type tlv struct {
	tag  byte
	body []byte
}

// readTLV reads one element from b, returning it and what follows.
func readTLV(b []byte) (tlv, []byte, error) {
	if len(b) < 2 || b[0]&0x1f == 0x1f {
		return tlv{}, nil, errBER
	}

	tag, n := b[0], int(b[1])
	b = b[2:]

	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 4 || len(b) < k {
			return tlv{}, nil, errBER // indefinite lengths and over 4 GB are not LDAP's
		}

		n = 0
		for _, c := range b[:k] {
			n = n<<8 | int(c)
		}

		b = b[k:]
	}

	if n < 0 || n > len(b) {
		return tlv{}, nil, errBER
	}

	return tlv{tag: tag, body: b[:n]}, b[n:], nil
}

// elements splits contents into its elements.
func elements(b []byte) ([]tlv, error) {
	var out []tlv

	for len(b) > 0 {
		t, rest, err := readTLV(b)
		if err != nil {
			return nil, err
		}

		out = append(out, t)
		b = rest
	}

	return out, nil
}

// encLen is a DER length.
func encLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}

	var l []byte
	for ; n > 0; n >>= 8 {
		l = append([]byte{byte(n)}, l...)
	}

	return append([]byte{0x80 | byte(len(l))}, l...)
}

// enc is an element: tag and contents.
func enc(tag byte, parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}

	return append(append([]byte{tag}, encLen(len(body))...), body...)
}

func encInt(tag byte, v int64) []byte {
	var b []byte

	for {
		b = append([]byte{byte(v)}, b...)
		v >>= 8

		if (v == 0 && b[0]&0x80 == 0) || (v == -1 && b[0]&0x80 != 0) {
			break
		}
	}

	return enc(tag, b)
}

func encOctets(tag byte, s []byte) []byte { return enc(tag, s) }

func encBool(tag byte, v bool) []byte {
	if v {
		return enc(tag, []byte{0xff})
	}

	return enc(tag, []byte{0})
}

func decInt(t tlv) (int64, error) {
	if len(t.body) == 0 || len(t.body) > 8 {
		return 0, errBER
	}

	v := int64(int8(t.body[0]))
	for _, c := range t.body[1:] {
		v = v<<8 | int64(c)
	}

	return v, nil
}

// Result is an LDAPResult (RFC 4511 4.1.9) that is not success.
type Result struct {
	Code       int
	MatchedDN  string
	Diagnostic string
}

func (r *Result) Error() string {
	return fmt.Sprintf("ldap: result %d (%s): %s", r.Code, resultName(r.Code), r.Diagnostic)
}

// Result codes this package acts on.
const (
	ResultSuccess            = 0
	ResultSaslBindInProgress = 14
)

func resultName(c int) string {
	switch c {
	case 0:
		return "success"
	case 1:
		return "operationsError"
	case 7:
		return "authMethodNotSupported"
	case 8:
		return "strongerAuthRequired"
	case 14:
		return "saslBindInProgress"
	case 32:
		return "noSuchObject"
	case 48:
		return "inappropriateAuthentication"
	case 49:
		return "invalidCredentials"
	case 50:
		return "insufficientAccessRights"
	case 53:
		return "unwillingToPerform"
	}

	return "other"
}

// decResult reads an LDAPResult's components, returning the elements after
// them (a bind's serverSaslCreds, an extended response's name and value).
func decResult(body []byte) (Result, []tlv, error) {
	es, err := elements(body)
	if err != nil || len(es) < 3 {
		return Result{}, nil, errBER
	}

	code, err := decInt(es[0])
	if err != nil {
		return Result{}, nil, err
	}

	return Result{Code: int(code), MatchedDN: string(es[1].body), Diagnostic: string(es[2].body)}, es[3:], nil
}

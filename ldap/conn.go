package ldap

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/SorinS/krb5/client"
	"github.com/SorinS/krb5/gsskrb5"
)

// Protocol operations' tags (RFC 4511 4.2 to 4.12).
const (
	opBindRequest      = classApplication | constructed | 0
	opBindResponse     = classApplication | constructed | 1
	opUnbindRequest    = classApplication | 2
	opSearchRequest    = classApplication | constructed | 3
	opSearchEntry      = classApplication | constructed | 4
	opSearchDone       = classApplication | constructed | 5
	opSearchReference  = classApplication | constructed | 19
	opExtendedRequest  = classApplication | constructed | 23
	opExtendedResponse = classApplication | constructed | 24
)

// maxMessage bounds what is read of one message (a wrapped one too).
const maxMessage = 16 << 20

// Conn is a connection to an LDAP server, one operation at a time.
type Conn struct {
	c    net.Conn
	r    *bufio.Reader
	mu   sync.Mutex
	id   int64
	sasl *gsskrb5.SASL // the security layer, once bound with one
	// Plain messages unwrapped and not yet read.
	pending []byte
	// Timeout for each operation (0: none).
	Timeout time.Duration
}

// Dial connects to the LDAP server at addr (host:port).
func Dial(addr string) (*Conn, error) {
	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	return NewConn(c), nil
}

// NewConn makes an LDAP connection of c.
func NewConn(c net.Conn) *Conn {
	return &Conn{c: c, r: bufio.NewReader(c), Timeout: 30 * time.Second}
}

// Close unbinds and closes the connection.
func (l *Conn) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.id++
	_ = l.write(enc(0x30, encInt(0x02, l.id), enc(opUnbindRequest)))

	return l.c.Close()
}

// write sends a message, wrapped when a layer is in force.
func (l *Conn) write(msg []byte) error {
	if l.Timeout > 0 {
		_ = l.c.SetDeadline(time.Now().Add(l.Timeout))
	}

	if l.sasl != nil {
		w, err := l.sasl.WrapMessage(msg)
		if err != nil {
			return err
		}

		msg = w
	}

	_, err := l.c.Write(msg)

	return err
}

// read returns the next message: id, operation, its body.
func (l *Conn) read() (int64, tlv, error) {
	if l.Timeout > 0 {
		_ = l.c.SetDeadline(time.Now().Add(l.Timeout))
	}

	if l.sasl != nil && l.sasl.Layer() != gsskrb5.LayerNone {
		// Wrapped buffers until a whole message is in: RFC 4752 lets a
		// message span buffers, and a buffer hold several.
		for {
			if len(l.pending) > 0 {
				m, rest, err := readTLV(l.pending)
				if err == nil {
					l.pending = rest
					return parseMessage(m)
				}

				if !errors.Is(err, errShort) {
					return 0, tlv{}, err
				}

				if len(l.pending) > maxMessage {
					return 0, tlv{}, fmt.Errorf("ldap: a message of more than %d bytes", maxMessage)
				}
			}

			var n [4]byte
			if _, err := io.ReadFull(l.r, n[:]); err != nil {
				return 0, tlv{}, err
			}

			size := binary.BigEndian.Uint32(n[:])
			if size > maxMessage {
				return 0, tlv{}, fmt.Errorf("ldap: a wrapped message of %d bytes", size)
			}

			w := make([]byte, size)
			if _, err := io.ReadFull(l.r, w); err != nil {
				return 0, tlv{}, err
			}

			p, err := l.sasl.UnwrapMessage(w)
			if err != nil {
				return 0, tlv{}, err
			}

			l.pending = append(l.pending, p...)
		}
	}

	m, err := readMessage(l.r)
	if err != nil {
		return 0, tlv{}, err
	}

	return parseMessage(m)
}

// readMessage reads one BER element off r.
func readMessage(r *bufio.Reader) (tlv, error) {
	h := make([]byte, 2)
	if _, err := io.ReadFull(r, h); err != nil {
		return tlv{}, err
	}

	if h[1]&0x80 != 0 {
		k := int(h[1] & 0x7f)
		if k == 0 || k > 4 {
			return tlv{}, errBER
		}

		ext := make([]byte, k)
		if _, err := io.ReadFull(r, ext); err != nil {
			return tlv{}, err
		}

		h = append(h, ext...)
	}

	_, _, n := lengthOf(h)
	if n < 0 || n > maxMessage {
		return tlv{}, fmt.Errorf("ldap: a message of %d bytes", n)
	}

	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return tlv{}, err
	}

	m, _, err := readTLV(append(h, body...))

	return m, err
}

func lengthOf(h []byte) (byte, int, int) {
	if h[1]&0x80 == 0 {
		return h[0], 2, int(h[1])
	}

	n := 0
	for _, c := range h[2:] {
		n = n<<8 | int(c)
	}

	return h[0], len(h), n
}

// parseMessage splits an LDAPMessage: its id and protocol operation.
func parseMessage(m tlv) (int64, tlv, error) {
	if m.tag != 0x30 {
		return 0, tlv{}, errBER
	}

	es, err := elements(m.body)
	if err != nil || len(es) < 2 {
		return 0, tlv{}, errBER
	}

	id, err := decInt(es[0])

	return id, es[1], err
}

// roundTrip sends an operation and reads the reply with its id (search
// results come through each, for which entries are passed).
func (l *Conn) roundTrip(op []byte, each func(tlv) error) (tlv, error) {
	l.id++
	id := l.id

	if err := l.write(enc(0x30, encInt(0x02, id), op)); err != nil {
		return tlv{}, err
	}

	for {
		mid, o, err := l.read()
		if err != nil {
			return tlv{}, err
		}

		if mid == 0 && o.tag == opExtendedResponse {
			// A notice of disconnection (RFC 4511 4.4.1).
			res, _, _ := decResult(o.body)
			return tlv{}, fmt.Errorf("ldap: the server disconnects: %w", &res)
		}

		if mid != id {
			continue
		}

		if each != nil && (o.tag == opSearchEntry || o.tag == opSearchReference) {
			if err := each(o); err != nil {
				return tlv{}, err
			}

			continue
		}

		return o, nil
	}
}

// BindGSSAPI binds with SASL GSSAPI (RFC 4752): a context with the client
// cl to service ("ldap@dc.example.com"), and the layer chosen from layers
// (gsskrb5.Layer*: the strongest the server offers). After it, messages
// travel under that layer.
func (l *Conn) BindGSSAPI(cl *client.Client, service string, layers byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	s := gsskrb5.NewSASL(cl, layers)

	tok, _, err := s.InitSecContext(service, nil)
	if err != nil {
		return err
	}

	bind := func(creds []byte, withCreds bool) (Result, []byte, error) {
		sasl := [][]byte{encOctets(0x04, []byte("GSSAPI"))}
		if withCreds {
			sasl = append(sasl, encOctets(0x04, creds))
		}

		op := enc(opBindRequest, encInt(0x02, 3), encOctets(0x04, nil), enc(classContext|constructed|3, sasl...))

		o, err := l.roundTrip(op, nil)
		if err != nil {
			return Result{}, nil, err
		}

		if o.tag != opBindResponse {
			return Result{}, nil, fmt.Errorf("ldap: a bind answered with operation %#x", o.tag)
		}

		res, rest, err := decResult(o.body)
		if err != nil {
			return res, nil, err
		}

		var serverCreds []byte

		for _, e := range rest {
			if e.tag == classContext|7 {
				serverCreds = e.body
			}
		}

		return res, serverCreds, nil
	}

	// Our context token; the server's AP-REP comes back.
	res, creds, err := bind(tok, true)
	if err != nil {
		return err
	}

	if res.Code != ResultSaslBindInProgress {
		return &res
	}

	if _, _, err = s.InitSecContext(service, creds); err != nil {
		return err
	}

	// An empty response; the server's offer of layers comes back.
	res, creds, err = bind(nil, false)
	if err != nil {
		return err
	}

	if res.Code != ResultSaslBindInProgress {
		return &res
	}

	choice, err := s.NegotiateSaslAuth(creds, "")
	if err != nil {
		return err
	}

	res, _, err = bind(choice, true)
	if err != nil {
		return err
	}

	if res.Code != ResultSuccess {
		return &res
	}

	if s.Layer() != gsskrb5.LayerNone {
		l.sasl = s
	}

	return nil
}

// Layer returns the security layer in force (gsskrb5.Layer*), LayerNone
// when there is none.
func (l *Conn) Layer() byte {
	if l.sasl == nil {
		return gsskrb5.LayerNone
	}

	return l.sasl.Layer()
}

// WhoAmI asks who the server takes us for (RFC 4532): "u:DOMAIN\user",
// "dn:...", or "" for anonymous.
func (l *Conn) WhoAmI() (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	op := enc(opExtendedRequest, encOctets(classContext|0, []byte("1.3.6.1.4.1.4203.1.11.3")))

	o, err := l.roundTrip(op, nil)
	if err != nil {
		return "", err
	}

	if o.tag != opExtendedResponse {
		return "", errors.New("ldap: Who am I? answered with another operation")
	}

	res, rest, err := decResult(o.body)
	if err != nil {
		return "", err
	}

	if res.Code != ResultSuccess {
		return "", &res
	}

	for _, e := range rest {
		if e.tag == classContext|11 {
			return string(e.body), nil
		}
	}

	return "", nil
}

// Scopes of a search.
const (
	ScopeBase     = 0
	ScopeOne      = 1
	ScopeSubtree  = 2
	derefNever    = 0
	searchMaxSize = 1000
)

// Entry is a search result: its DN and attributes (every value, raw).
type Entry struct {
	DN         string
	Attributes map[string][][]byte
}

// Get returns the first value of the attribute, or "".
func (e *Entry) Get(attr string) string {
	if v := e.Attributes[attr]; len(v) > 0 {
		return string(v[0])
	}

	return ""
}

// Search searches from base with the filter (RFC 4515's string form),
// returning the attributes asked for (all when none are).
func (l *Conn) Search(base string, scope int, filter string, attrs ...string) ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := encodeFilter(filter)
	if err != nil {
		return nil, err
	}

	var as [][]byte
	for _, a := range attrs {
		as = append(as, encOctets(0x04, []byte(a)))
	}

	op := enc(opSearchRequest, encOctets(0x04, []byte(base)), encInt(0x0a, int64(scope)), encInt(0x0a, derefNever),
		encInt(0x02, searchMaxSize), encInt(0x02, 0), encBool(0x01, false), f, enc(0x30, as...))

	var entries []Entry

	o, err := l.roundTrip(op, func(t tlv) error {
		if t.tag != opSearchEntry {
			return nil // references are not followed
		}

		e, err := decodeEntry(t.body)
		if err != nil {
			return err
		}

		entries = append(entries, e)

		return nil
	})
	if err != nil {
		return nil, err
	}

	if o.tag != opSearchDone {
		return nil, errors.New("ldap: a search answered with another operation")
	}

	res, _, err := decResult(o.body)
	if err != nil {
		return nil, err
	}

	if res.Code != ResultSuccess {
		return entries, &res
	}

	return entries, nil
}

func decodeEntry(body []byte) (Entry, error) {
	es, err := elements(body)
	if err != nil || len(es) != 2 {
		return Entry{}, errBER
	}

	e := Entry{DN: string(es[0].body), Attributes: map[string][][]byte{}}

	attrs, err := elements(es[1].body)
	if err != nil {
		return e, err
	}

	for _, a := range attrs {
		parts, err := elements(a.body)
		if err != nil || len(parts) != 2 {
			return e, errBER
		}

		vals, err := elements(parts[1].body)
		if err != nil {
			return e, err
		}

		name := string(parts[0].body)
		for _, v := range vals {
			e.Attributes[name] = append(e.Attributes[name], append([]byte(nil), v.body...))
		}
	}

	return e, nil
}

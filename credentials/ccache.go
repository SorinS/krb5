package credentials

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/SorinS/krb5/iana/nametype"
	"github.com/SorinS/krb5/types"
)

const (
	headerFieldTagKDCOffset = 1

	// The realm and first name component of a cache's configuration
	// entries (MIT's krb5_cc_set_config).
	configRealm  = "X-CACHECONF:"
	configPrefix = "krb5_ccache_conf_data"
)

// CCache is the file credentials cache as define here: https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html
type CCache struct {
	Version          uint8
	Header           header
	DefaultPrincipal principal
	Credentials      []*Credential
	Path             string
}

type header struct {
	length uint16
	fields []headerField
}

type headerField struct {
	tag    uint16
	length uint16
	value  []byte
}

// Principal is a credential cache's principal: a name and its realm.
type Principal struct {
	Realm         string
	PrincipalName types.PrincipalName
}

// Credential cache entry principal struct.
type principal = Principal

// Credential holds a Kerberos client's ccache credential information.
type Credential struct {
	Client       principal
	Server       principal
	Key          types.EncryptionKey
	AuthTime     time.Time
	StartTime    time.Time
	EndTime      time.Time
	RenewTill    time.Time
	IsSKey       bool
	TicketFlags  asn1.BitString
	Addresses    []types.HostAddress
	AuthData     []types.AuthorizationDataEntry
	Ticket       []byte
	SecondTicket []byte
}

// LoadCCache loads a credential cache file into a CCache type.
func LoadCCache(cpath string) (*CCache, error) {
	c := new(CCache)

	b, err := os.ReadFile(cpath)
	if err != nil {
		return c, err
	}

	if len(b) < 10 {
		return c, errors.New("Invalid credential cache data: file too short")
	}

	err = c.Unmarshal(b)
	c.Path = cpath

	return c, err
}

// NewV4CCache returns an empty credential cache, of version 4 (MIT's
// default), for the client cname in realm.
func NewV4CCache(cname types.PrincipalName, realm string) *CCache {
	return &CCache{
		Version:          4,
		DefaultPrincipal: Principal{Realm: realm, PrincipalName: cname},
	}
}

// reader reads a cache's bytes, remembering the first error: past the end,
// every read gives zero values.
type reader struct {
	b   []byte
	p   int
	e   binary.ByteOrder
	err error
}

func (r *reader) bytes(n int) []byte {
	if r.err != nil {
		return nil
	}

	if n < 0 || n > len(r.b)-r.p {
		r.err = fmt.Errorf("invalid credential cache data: %d bytes wanted at %d of %d", n, r.p, len(r.b))
		return nil
	}

	v := make([]byte, n)
	copy(v, r.b[r.p:r.p+n])
	r.p += n

	return v
}

func (r *reader) u8() uint8 {
	if b := r.bytes(1); b != nil {
		return b[0]
	}

	return 0
}

func (r *reader) u16() uint16 {
	if b := r.bytes(2); b != nil {
		return r.e.Uint16(b)
	}

	return 0
}

func (r *reader) u32() uint32 {
	if b := r.bytes(4); b != nil {
		return r.e.Uint32(b)
	}

	return 0
}

// data reads a counted octet string.
func (r *reader) data() []byte {
	n := r.u32()
	if n > uint32(len(r.b)) {
		r.err = fmt.Errorf("invalid credential cache data: a length of %d", n)
		return nil
	}

	return r.bytes(int(n))
}

// time reads a timestamp: seconds since the epoch, unsigned (MIT's
// krb5_timestamp read as such, so past 2038).
func (r *reader) time() time.Time {
	return time.Unix(int64(r.u32()), 0)
}

// Unmarshal a byte slice of credential cache data into CCache type.
func (c *CCache) Unmarshal(b []byte) error {
	if len(b) < 2 || b[0] != 5 {
		return errors.New("Invalid credential cache data. First byte does not equal 5")
	}

	c.Version = b[1]
	if c.Version < 1 || c.Version > 4 {
		return errors.New("Invalid credential cache data. Keytab version is not within 1 to 4")
	}

	// Versions 1 and 2 are in the writer's byte order, which MIT took to be
	// the reader's too; 3 and 4 are big-endian.
	r := &reader{b: b, p: 2, e: binary.BigEndian}
	if c.Version == 1 || c.Version == 2 {
		r.e = binary.NativeEndian
	}

	c.Header = header{}
	c.Credentials = nil

	if c.Version == 4 {
		if err := parseHeader(r, c); err != nil {
			return err
		}
	}

	c.DefaultPrincipal = parsePrincipal(r, c)
	for r.err == nil && r.p < len(b) {
		cred := parseCredential(r, c)
		if r.err != nil {
			break
		}

		c.Credentials = append(c.Credentials, cred)
	}

	return r.err
}

// parseHeader reads a version 4 cache's header: tagged fields, of which MIT
// defines only the KDC time offset (tag 1); others are kept, unread.
func parseHeader(r *reader, c *CCache) error {
	if c.Version != 4 {
		return errors.New("Credentials cache version is not 4 so there is no header to parse.")
	}

	h := header{length: r.u16()}
	end := r.p + int(h.length)

	if end > len(r.b) {
		return errors.New("Invalid credential cache header: longer than the cache")
	}

	for r.err == nil && r.p < end {
		f := headerField{tag: r.u16(), length: r.u16()}
		if r.p+int(f.length) > end {
			return errors.New("Invalid credential cache header found")
		}

		f.value = r.bytes(int(f.length))
		if f.tag == headerFieldTagKDCOffset && !f.valid() {
			return errors.New("Invalid credential cache header found")
		}

		h.fields = append(h.fields, f)
	}

	c.Header = h

	return r.err
}

// parsePrincipal reads a principal.
func parsePrincipal(r *reader, c *CCache) (princ principal) {
	if c.Version != 1 {
		// Name Type is omitted in version 1.
		princ.PrincipalName.NameType = int32(r.u32())
	}

	nc := int(r.u32())
	if c.Version == 1 {
		// In version 1 the number of components includes the realm. Minus 1 to make consistent with version 2.
		nc--
	}

	if nc < 0 || nc > len(r.b) {
		r.err = fmt.Errorf("invalid credential cache data: %d name components", nc)
		return princ
	}

	princ.Realm = string(r.data())
	for i := 0; i < nc && r.err == nil; i++ {
		princ.PrincipalName.NameString = append(princ.PrincipalName.NameString, string(r.data()))
	}

	return princ
}

// parseCredential reads a credential.
func parseCredential(r *reader, c *CCache) *Credential {
	cred := new(Credential)
	cred.Client = parsePrincipal(r, c)
	cred.Server = parsePrincipal(r, c)

	cred.Key.KeyType = int32(int16(r.u16()))
	if c.Version == 3 {
		// Version 3 has the key's enctype twice.
		cred.Key.KeyType = int32(int16(r.u16()))
	}

	cred.Key.KeyValue = r.data()
	cred.AuthTime = r.time()
	cred.StartTime = r.time()
	cred.EndTime = r.time()
	cred.RenewTill = r.time()
	cred.IsSKey = r.u8() != 0

	cred.TicketFlags = types.NewKrbFlags()
	if f := r.bytes(4); f != nil {
		cred.TicketFlags.Bytes = f
	}

	n := r.u32()
	if n > uint32(len(r.b)) {
		r.err = fmt.Errorf("invalid credential cache data: %d addresses", n)
		return cred
	}

	cred.Addresses = make([]types.HostAddress, 0, n)
	for i := uint32(0); i < n && r.err == nil; i++ {
		a := types.HostAddress{AddrType: int32(int16(r.u16()))}
		a.Address = r.data()
		cred.Addresses = append(cred.Addresses, a)
	}

	n = r.u32()
	if n > uint32(len(r.b)) {
		r.err = fmt.Errorf("invalid credential cache data: %d authorization data entries", n)
		return cred
	}

	cred.AuthData = make([]types.AuthorizationDataEntry, 0, n)
	for i := uint32(0); i < n && r.err == nil; i++ {
		a := types.AuthorizationDataEntry{ADType: int32(int16(r.u16()))}
		a.ADData = r.data()
		cred.AuthData = append(cred.AuthData, a)
	}

	cred.Ticket = r.data()
	cred.SecondTicket = r.data()

	return cred
}

// writer builds a cache's bytes, big-endian (versions 3 and 4).
type writer struct {
	b []byte
}

func (w *writer) u8(v uint8)   { w.b = append(w.b, v) }
func (w *writer) u16(v uint16) { w.b = binary.BigEndian.AppendUint16(w.b, v) }
func (w *writer) u32(v uint32) { w.b = binary.BigEndian.AppendUint32(w.b, v) }

func (w *writer) data(d []byte) {
	w.u32(uint32(len(d)))
	w.b = append(w.b, d...)
}

func (w *writer) time(t time.Time) {
	if t.IsZero() || t.Unix() <= 0 {
		w.u32(0)
		return
	}

	w.u32(uint32(t.Unix()))
}

func (w *writer) principal(p principal) {
	w.u32(uint32(p.PrincipalName.NameType))
	w.u32(uint32(len(p.PrincipalName.NameString)))
	w.data([]byte(p.Realm))

	for _, s := range p.PrincipalName.NameString {
		w.data([]byte(s))
	}
}

// Marshal the cache in MIT's FILE format: version 4, unless the cache is
// of version 3 (versions 1 and 2, in the host's byte order, are read but
// not written). A version 4 cache always has the KDC time offset field,
// zero when unset, as MIT writes it.
func (c *CCache) Marshal() ([]byte, error) {
	version := c.Version
	if version == 0 {
		version = 4
	}

	if version != 3 && version != 4 {
		return nil, fmt.Errorf("credential cache version %d is not written: only 3 and 4", version)
	}

	w := &writer{b: []byte{5, version}}

	if version == 4 {
		fields := c.Header.fields
		if !c.hasHeaderField(headerFieldTagKDCOffset) {
			fields = append([]headerField{{tag: headerFieldTagKDCOffset, length: 8, value: make([]byte, 8)}}, fields...)
		}

		var h writer
		for _, f := range fields {
			h.u16(f.tag)
			h.u16(uint16(len(f.value)))
			h.b = append(h.b, f.value...)
		}

		if len(h.b) > 0xffff {
			return nil, errors.New("credential cache header too long")
		}

		w.u16(uint16(len(h.b)))
		w.b = append(w.b, h.b...)
	}

	w.principal(c.DefaultPrincipal)

	for _, cred := range c.Credentials {
		w.principal(cred.Client)
		w.principal(cred.Server)
		w.u16(uint16(cred.Key.KeyType))

		if version == 3 {
			w.u16(uint16(cred.Key.KeyType))
		}

		w.data(cred.Key.KeyValue)
		w.time(cred.AuthTime)
		w.time(cred.StartTime)
		w.time(cred.EndTime)
		w.time(cred.RenewTill)

		if cred.IsSKey {
			w.u8(1)
		} else {
			w.u8(0)
		}

		flags := make([]byte, 4)
		copy(flags, cred.TicketFlags.Bytes)
		w.b = append(w.b, flags...)

		w.u32(uint32(len(cred.Addresses)))
		for _, a := range cred.Addresses {
			w.u16(uint16(a.AddrType))
			w.data(a.Address)
		}

		w.u32(uint32(len(cred.AuthData)))
		for _, a := range cred.AuthData {
			w.u16(uint16(a.ADType))
			w.data(a.ADData)
		}

		w.data(cred.Ticket)
		w.data(cred.SecondTicket)
	}

	return w.b, nil
}

// Save writes the cache to the file path (FILE: stripped), readable and
// writable by its owner only, as MIT makes it: to a new file in the same
// directory, renamed over the old.
func (c *CCache) Save(path string) error {
	path = strings.TrimPrefix(path, "FILE:")

	b, err := c.Marshal()
	if err != nil {
		return err
	}

	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return err
	}

	tmp := f.Name()

	if err = f.Chmod(0o600); err == nil {
		if _, err = f.Write(b); err == nil {
			err = f.Sync()
		}
	}

	if cerr := f.Close(); err == nil {
		err = cerr
	}

	if err == nil {
		err = os.Rename(tmp, path)
	}

	if err != nil {
		os.Remove(tmp)
		return err
	}

	c.Path = path

	return nil
}

func (c *CCache) hasHeaderField(tag uint16) bool {
	for _, f := range c.Header.fields {
		if f.tag == tag {
			return true
		}
	}

	return false
}

// KDCOffset returns the KDC's time offset the cache records (version 4):
// the KDC's clock less the client's, and whether the cache has it set.
func (c *CCache) KDCOffset() (time.Duration, bool) {
	for _, f := range c.Header.fields {
		if f.tag == headerFieldTagKDCOffset && len(f.value) == 8 {
			sec := int32(binary.BigEndian.Uint32(f.value[:4]))
			usec := int32(binary.BigEndian.Uint32(f.value[4:]))
			d := time.Duration(sec)*time.Second + time.Duration(usec)*time.Microsecond

			return d, d != 0
		}
	}

	return 0, false
}

// SetKDCOffset records the KDC's time offset in the cache's header (the
// KDC's clock less the client's), as MIT keeps it for kdc_timesync.
func (c *CCache) SetKDCOffset(d time.Duration) {
	v := make([]byte, 8)
	sec := d / time.Second
	usec := (d % time.Second) / time.Microsecond

	if usec < 0 {
		sec--
		usec += 1000000
	}

	binary.BigEndian.PutUint32(v[:4], uint32(int32(sec)))
	binary.BigEndian.PutUint32(v[4:], uint32(int32(usec)))

	for i, f := range c.Header.fields {
		if f.tag == headerFieldTagKDCOffset {
			c.Header.fields[i].value = v
			c.Header.fields[i].length = 8

			return
		}
	}

	c.Header.fields = append([]headerField{{tag: headerFieldTagKDCOffset, length: 8, value: v}}, c.Header.fields...)
}

// AddCredential puts the credential in the cache, in place of one for the
// same client and server (as MIT's krb5_cc_store_cred does).
func (c *CCache) AddCredential(cred *Credential) {
	for i, old := range c.Credentials {
		if old.Server.Realm == cred.Server.Realm && old.Server.PrincipalName.Equal(cred.Server.PrincipalName) &&
			old.Client.Realm == cred.Client.Realm && old.Client.PrincipalName.Equal(cred.Client.PrincipalName) {
			c.Credentials[i] = cred
			return
		}
	}

	c.Credentials = append(c.Credentials, cred)
}

// configServer is the server principal of a configuration entry for key
// (and the principal it is about, if any): krb5_ccache_conf_data/key[/principal]@X-CACHECONF:.
func configServer(key, principal string) Principal {
	names := []string{configPrefix, key}
	if principal != "" {
		names = append(names, principal)
	}

	return Principal{Realm: configRealm, PrincipalName: types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: names}}
}

// SetConfig sets a configuration entry, as MIT's krb5_cc_set_config does:
// key ("fast_avail", "pa_type", ...) about the principal (its unparsed
// name, as "krbtgt/EXAMPLE.COM@EXAMPLE.COM", or "" for the cache as a
// whole), with the value.
func (c *CCache) SetConfig(key, principal string, value []byte) {
	c.AddCredential(&Credential{
		Client:      c.DefaultPrincipal,
		Server:      configServer(key, principal),
		TicketFlags: types.NewKrbFlags(),
		Ticket:      value,
	})
}

// Config returns a configuration entry's value (see SetConfig).
func (c *CCache) Config(key, principal string) ([]byte, bool) {
	s := configServer(key, principal)

	for _, cred := range c.Credentials {
		if cred.Server.Realm == s.Realm && cred.Server.PrincipalName.Equal(s.PrincipalName) {
			return cred.Ticket, true
		}
	}

	return nil, false
}

// GetClientPrincipalName returns a PrincipalName type for the client the credentials cache is for.
func (c *CCache) GetClientPrincipalName() types.PrincipalName {
	return c.DefaultPrincipal.PrincipalName
}

// GetClientRealm returns the reals of the client the credentials cache is for.
func (c *CCache) GetClientRealm() string {
	return c.DefaultPrincipal.Realm
}

// GetClientCredentials returns a Credentials object representing the client of the credentials cache.
func (c *CCache) GetClientCredentials() *Credentials {
	return &Credentials{
		username: c.DefaultPrincipal.PrincipalName.PrincipalNameString(),
		realm:    c.GetClientRealm(),
		cname:    c.DefaultPrincipal.PrincipalName,
	}
}

// Contains tests if the cache contains a credential for the provided server PrincipalName.
func (c *CCache) Contains(p types.PrincipalName) bool {
	for _, cred := range c.Credentials {
		if cred.Server.PrincipalName.Equal(p) {
			return true
		}
	}

	return false
}

// GetEntry returns a specific credential for the PrincipalName provided.
func (c *CCache) GetEntry(p types.PrincipalName) (*Credential, bool) {
	cred := new(Credential)

	var found bool

	for i := range c.Credentials {
		if c.Credentials[i].Server.PrincipalName.Equal(p) {
			cred = c.Credentials[i]
			found = true

			break
		}
	}

	if !found {
		return cred, false
	}

	return cred, true
}

// GetEntries filters out configuration entries an returns a slice of credentials.
func (c *CCache) GetEntries() []*Credential {
	creds := make([]*Credential, 0)

	for _, cred := range c.Credentials {
		// Filter out configuration entries.
		if strings.HasPrefix(cred.Server.Realm, "X-CACHECONF") {
			continue
		}

		creds = append(creds, cred)
	}

	return creds
}

// Reference: https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html
func (h *headerField) valid() bool {
	switch h.tag {
	case headerFieldTagKDCOffset:
		if h.length != 8 || len(h.value) != 8 {
			return false
		}

		return true
	}

	return false
}

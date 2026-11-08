// Package keytab implements Kerberos keytabs: https://web.mit.edu/kerberos/krb5-latest/doc/formats/keytab_file_format.html.
package keytab

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/SorinS/krb5/crypto"
	"github.com/SorinS/krb5/iana/patype"
	"github.com/SorinS/krb5/types"
)

const (
	keytabFirstByte byte = 05
)

// Keytab struct.
type Keytab struct {
	version uint8
	Entries []Entry
}

// Entry is one key in a keytab. Its fields may be read and set directly to
// manipulate a keytab (its timestamp, for example); use SetKVNO to change the
// key version, so the 8-bit and 32-bit forms stay consistent.
type Entry struct {
	Principal Principal
	Timestamp time.Time
	// KVNO8 is the key version in the format's original 8-bit field; KVNO is
	// the full version from the 32-bit extension (they differ only for a
	// version above 255). SetKVNO sets both; prefer it over setting either.
	KVNO8 uint8
	Key   types.EncryptionKey
	KVNO  uint32
}

func (e Entry) String() string {
	return fmt.Sprintf("% 4d %s %-56s %2d %-64x",
		e.KVNO8,
		e.Timestamp.Format("02/01/06 15:04:05"),
		e.Principal.String(),
		e.Key.KeyType,
		e.Key.KeyValue,
	)
}

// SetKVNO sets the entry's key version, in both the 8-bit field (low byte) and
// the 32-bit extension, so a version above 255 (Active Directory's can be) is
// written and read back whole.
func (e *Entry) SetKVNO(kvno uint32) {
	e.KVNO = kvno
	e.KVNO8 = uint8(kvno)
}

// SetTimestamp sets the entry's timestamp (when the key was made).
func (e *Entry) SetTimestamp(t time.Time) {
	e.Timestamp = t
}

// Principal is a keytab entry's principal. Its fields may be read and set
// directly.
type Principal struct {
	NumComponents int16 `json:"-"`
	Realm         string
	Components    []string
	NameType      int32
}

func (p Principal) String() string {
	return fmt.Sprintf("%s@%s", strings.Join(p.Components, "/"), p.Realm)
}

// New creates new, empty Keytab type.
func New() *Keytab {
	var e []Entry

	return &Keytab{
		version: 2,
		Entries: e,
	}
}

// GetEncryptionKey returns the EncryptionKey from the Keytab for the newest entry with the required kvno, etype and matching principal.
// If the kvno is zero then the latest kvno will be returned. The kvno is also returned for.
func (kt *Keytab) GetEncryptionKey(princName types.PrincipalName, realm string, kvno int, etype int32) (types.EncryptionKey, int, error) {
	var (
		key types.EncryptionKey
		t   time.Time
		kv  int
	)

	for _, k := range kt.Entries {
		if k.Principal.Realm == realm && len(k.Principal.Components) == len(princName.NameString) &&
			k.Key.KeyType == etype &&
			(k.KVNO == uint32(kvno) || kvno == 0) &&
			k.Timestamp.After(t) {
			p := true

			for i, n := range k.Principal.Components {
				if princName.NameString[i] != n {
					p = false
					break
				}
			}

			if p {
				key = k.Key
				kv = int(k.KVNO)
				t = k.Timestamp
			}
		}
	}

	if len(key.KeyValue) < 1 {
		return key, 0, fmt.Errorf("matching key not found in keytab. Looking for %q realm: %v kvno: %v etype: %v", princName.PrincipalNameString(), realm, kvno, etype)
	}

	return key, kv, nil
}

// Create a new Keytab entry.
func newEntry() Entry {
	var b []byte

	return Entry{
		Principal: newPrincipal(),
		Timestamp: time.Time{},
		KVNO8:     0,
		Key: types.EncryptionKey{
			KeyType:  0,
			KeyValue: b,
		},
		KVNO: 0,
	}
}

func (kt Keytab) String() string {
	var s string

	s = `KVNO Timestamp         Principal                                                ET Key
---- ----------------- -------------------------------------------------------- -- ----------------------------------------------------------------
`
	for _, e := range kt.Entries {
		s += e.String() + "\n"
	}

	return s
}

// AddEntry adds an entry to the keytab. The password should be provided in
// plain text and it will be converted using the defined enctype to be stored.
// The key is salted with the principal's default salt (REALM followed by the
// name components, as MIT and AD form it for an account's own name); for an
// account whose salt differs, or a key version above 255, use
// AddEntryWithSalt.
func (kt *Keytab) AddEntry(principalName, realm, password string, ts time.Time, kvno uint8, encType int32) error {
	return kt.AddEntryWithSalt(principalName, realm, password, "", ts, uint32(kvno), encType)
}

// AddEntryWithSalt adds an entry whose key is derived from the password and an
// explicit salt. An empty salt means the principal's default, as AddEntry
// uses. Active Directory salts a user by its UPN or sAMAccountName rather than
// the SPN, so a keytab for a service account made by this library needs that
// account's salt here to match the key AD holds.
//
// kvno is a uint32: Active Directory key versions can exceed 255, which the
// keytab's 8-bit field cannot hold. Such a version is written in the format's
// 32-bit extension (readers that understand it, including this package, use
// it), with the low byte in the 8-bit field as MIT does.
func (kt *Keytab) AddEntryWithSalt(principalName, realm, password, salt string, ts time.Time, kvno uint32, encType int32) error {
	princ, _ := types.ParseSPNString(principalName)

	var pas types.PADataSequence
	if salt != "" {
		pas = types.PADataSequence{{PADataType: patype.PA_PW_SALT, PADataValue: []byte(salt)}}
	}

	key, _, err := crypto.GetKeyFromPassword(password, princ, realm, encType, pas)
	if err != nil {
		return err
	}

	ktep := newPrincipal()

	ktep.NumComponents = int16(len(princ.NameString))
	if kt.version == 1 {
		ktep.NumComponents += 1
	}

	ktep.Realm = realm
	ktep.Components = princ.NameString
	ktep.NameType = princ.NameType

	e := newEntry()
	e.Principal = ktep
	e.Timestamp = ts
	e.KVNO8 = uint8(kvno)
	e.KVNO = kvno
	e.Key = key

	kt.Entries = append(kt.Entries, e)

	return nil
}

// Create a new principal.
func newPrincipal() Principal {
	var c []string

	return Principal{
		NumComponents: 0,
		Realm:         "",
		Components:    c,
		NameType:      0,
	}
}

// Load a Keytab file into a Keytab type.
func Load(ktPath string) (*Keytab, error) {
	kt := new(Keytab)

	b, err := os.ReadFile(ktPath)
	if err != nil {
		return kt, err
	}

	err = kt.Unmarshal(b)

	return kt, err
}

// Marshal keytab into byte slice.
func (kt *Keytab) Marshal() ([]byte, error) {
	b := []byte{keytabFirstByte, kt.version}
	for _, e := range kt.Entries {
		eb, err := e.marshal(int(kt.version))
		if err != nil {
			return b, err
		}

		b = append(b, eb...)
	}

	return b, nil
}

// Write the keytab bytes to io.Writer.
// Returns the number of bytes written.
func (kt *Keytab) Write(w io.Writer) (int, error) {
	b, err := kt.Marshal()
	if err != nil {
		return 0, fmt.Errorf("error marshaling keytab: %w", err)
	}

	return w.Write(b)
}

// Unmarshal byte slice of Keytab data into Keytab type.
func (kt *Keytab) Unmarshal(b []byte) error {
	if len(b) < 2 {
		return fmt.Errorf("byte array is less than 2 bytes: %d", len(b))
	}

	if b[0] != keytabFirstByte {
		return errors.New("invalid keytab data. First byte does not equal 5")
	}

	kt.version = b[1]
	if kt.version != 1 && kt.version != 2 {
		return errors.New("invalid keytab data. Keytab version is neither 1 nor 2")
	}

	// Version 1 of the file format uses native byte order for integer representations. Version 2 always uses big-endian byte order.
	var endian binary.ByteOrder

	endian = binary.BigEndian
	if kt.version == 1 && isNativeEndianLittle() {
		endian = binary.LittleEndian
	}

	n := 2

	l, err := readInt32(b, &n, &endian)
	if err != nil {
		return err
	}

	for l != 0 {
		if l < 0 {
			l *= -1
			n += int(l)
		} else {
			if n < 0 {
				return fmt.Errorf("%d can't be less than zero", n)
			}

			if n+int(l) > len(b) {
				return fmt.Errorf("keytab data length %d is less than required %d", len(b), n+int(l))
			}

			eb := b[n : n+int(l)]
			n += int(l)
			ke := newEntry()

			var (
				p   int
				err error
			)

			if err = parsePrincipal(eb, &p, kt, &ke, &endian); err != nil {
				return err
			}

			if ke.Timestamp, err = readTimestamp(eb, &p, &endian); err != nil {
				return err
			}

			rei8, err := readInt8(eb, &p, &endian)
			if err != nil {
				return err
			}

			ke.KVNO8 = uint8(rei8)

			rei16, err := readInt16(eb, &p, &endian)
			if err != nil {
				return err
			}

			ke.Key.KeyType = int32(rei16)

			if rei16, err = readInt16(eb, &p, &endian); err != nil {
				return err
			}

			kl := int(rei16)

			if ke.Key.KeyValue, err = readBytes(eb, &p, kl, &endian); err != nil {
				return err
			}

			// The 32-bit key version overrides the 8-bit key version.
			// If at least 4 bytes are left after the other fields are read and they are non-zero
			// this indicates the 32-bit version is present.
			if len(eb)-p >= 4 {
				ri32, err := readInt32(eb, &p, &endian)
				if err != nil {
					return err
				}

				ke.KVNO = uint32(ri32)
			}

			if ke.KVNO == 0 {
				// Handles if the value from the last 4 bytes was zero and also if there are not the 4 bytes present. Makes sense to put the same value here as KVNO8.
				ke.KVNO = uint32(ke.KVNO8)
			}

			// Add the entry to the keytab.
			kt.Entries = append(kt.Entries, ke)
		}

		// Check if there are still 4 bytes left to read
		// Also check that n is greater than zero.
		if n < 0 || n > len(b) || len(b[n:]) < 4 {
			break
		}

		// Read the size of the next entry.
		if l, err = readInt32(b, &n, &endian); err != nil {
			return err
		}
	}

	return nil
}

func (e Entry) marshal(v int) (b []byte, err error) {
	pb, err := e.Principal.marshal(v)
	if err != nil {
		return b, err
	}

	b = append(b, pb...)

	var endian binary.ByteOrder = binary.BigEndian

	if v == 1 && isNativeEndianLittle() {
		endian = binary.LittleEndian
	}

	t := make([]byte, 9)
	endian.PutUint32(t[0:4], uint32(e.Timestamp.Unix()))

	t[4] = e.KVNO8

	endian.PutUint16(t[5:7], uint16(e.Key.KeyType))
	endian.PutUint16(t[7:9], uint16(len(e.Key.KeyValue)))

	b = append(b, t...)

	buf := new(bytes.Buffer)

	if err = binary.Write(buf, endian, e.Key.KeyValue); err != nil {
		return b, err
	}

	b = append(b, buf.Bytes()...)

	t = make([]byte, 4)
	endian.PutUint32(t, e.KVNO)

	b = append(b, t...)

	t = make([]byte, 4)
	endian.PutUint32(t, uint32(len(b)))

	b = append(t, b...)

	return b, nil
}

// Parse the Keytab bytes of a principal into a Keytab entry's principal.
func parsePrincipal(b []byte, p *int, kt *Keytab, ke *Entry, e *binary.ByteOrder) error {
	var err error

	ke.Principal.NumComponents, err = readInt16(b, p, e)
	if err != nil {
		return err
	}

	if kt.version == 1 {
		// In version 1 the number of components includes the realm. Minus 1 to make consistent with version 2.
		ke.Principal.NumComponents--
	}

	lenRealm, err := readInt16(b, p, e)
	if err != nil {
		return err
	}

	realmB, err := readBytes(b, p, int(lenRealm), e)
	if err != nil {
		return err
	}

	ke.Principal.Realm = string(realmB)
	for i := 0; i < int(ke.Principal.NumComponents); i++ {
		l, err := readInt16(b, p, e)
		if err != nil {
			return err
		}

		compB, err := readBytes(b, p, int(l), e)
		if err != nil {
			return err
		}

		ke.Principal.Components = append(ke.Principal.Components, string(compB))
	}

	if kt.version != 1 {
		// Name Type is omitted in version 1.
		ke.Principal.NameType, err = readInt32(b, p, e)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p Principal) marshal(v int) ([]byte, error) {
	// var b []byte.
	b := make([]byte, 2)

	var endian binary.ByteOrder

	endian = binary.BigEndian
	if v == 1 && isNativeEndianLittle() {
		endian = binary.LittleEndian
	}

	endian.PutUint16(b[0:], uint16(p.NumComponents))

	realm, err := marshalString(p.Realm, v)
	if err != nil {
		return b, err
	}

	b = append(b, realm...)

	for _, c := range p.Components {
		cb, err := marshalString(c, v)
		if err != nil {
			return b, err
		}

		b = append(b, cb...)
	}

	if v != 1 {
		t := make([]byte, 4)
		endian.PutUint32(t, uint32(p.NameType))
		b = append(b, t...)
	}

	return b, nil
}

func marshalString(s string, v int) ([]byte, error) {
	sb := []byte(s)
	b := make([]byte, 2)

	var endian binary.ByteOrder

	endian = binary.BigEndian
	if v == 1 && isNativeEndianLittle() {
		endian = binary.LittleEndian
	}

	endian.PutUint16(b[0:], uint16(len(sb)))

	buf := new(bytes.Buffer)

	err := binary.Write(buf, endian, sb)
	if err != nil {
		return b, err
	}

	b = append(b, buf.Bytes()...)

	return b, err
}

// Read bytes representing a timestamp.
func readTimestamp(b []byte, p *int, e *binary.ByteOrder) (time.Time, error) {
	i32, err := readInt32(b, p, e)
	if err != nil {
		return time.Time{}, err
	}

	return time.Unix(int64(i32), 0), nil
}

// Read bytes representing an eight bit integer.
func readInt8(b []byte, p *int, e *binary.ByteOrder) (i int8, err error) {
	if *p < 0 {
		return 0, fmt.Errorf("%d cannot be less than zero", *p)
	}

	if (*p + 1) > len(b) {
		return 0, fmt.Errorf("keytab data length %d is less than required %d", len(b), *p+1)
	}

	buf := bytes.NewBuffer(b[*p : *p+1])

	if err = binary.Read(buf, *e, &i); err != nil {
		return 0, fmt.Errorf("error reading bytes: %w", err)
	}

	*p++

	return
}

// Read bytes representing a sixteen bit integer.
func readInt16(b []byte, p *int, e *binary.ByteOrder) (i int16, err error) {
	if *p < 0 {
		return 0, fmt.Errorf("%d cannot be less than zero", *p)
	}

	if (*p + 2) > len(b) {
		return 0, fmt.Errorf("keytab data length %d is less than required %d", len(b), *p+2)
	}

	buf := bytes.NewBuffer(b[*p : *p+2])

	if err = binary.Read(buf, *e, &i); err != nil {
		return 0, fmt.Errorf("error reading bytes: %w", err)
	}

	*p += 2

	return
}

// Read bytes representing a thirty two bit integer.
func readInt32(b []byte, p *int, e *binary.ByteOrder) (i int32, err error) {
	if *p < 0 {
		return 0, fmt.Errorf("%d cannot be less than zero", *p)
	}

	if (*p + 4) > len(b) {
		return 0, fmt.Errorf("keytab data length %d is less than required %d", len(b), *p+4)
	}

	buf := bytes.NewBuffer(b[*p : *p+4])

	if err = binary.Read(buf, *e, &i); err != nil {
		return 0, fmt.Errorf("error occurred performing binary read: %w", err)
	}

	*p += 4

	return
}

func readBytes(b []byte, p *int, s int, e *binary.ByteOrder) ([]byte, error) {
	if s < 0 {
		return nil, fmt.Errorf("%d cannot be less than zero", s)
	}

	i := *p + s

	if i > len(b) {
		return nil, fmt.Errorf("keytab data length %d is less than required %d", len(b), i)
	}

	buf := bytes.NewBuffer(b[*p:i])

	r := make([]byte, s)

	if err := binary.Read(buf, *e, &r); err != nil {
		return nil, err
	}

	*p += s

	return r, nil
}

func isNativeEndianLittle() bool {
	var (
		x  = 0x012345678
		p  = unsafe.Pointer(&x)
		bp = (*[4]byte)(p)
	)

	var endian bool

	if bp[0]&0xff == 0x78&0xff {
		endian = true
	}

	return endian
}

// JSON return information about the keys held in the keytab in a JSON format.
func (kt *Keytab) JSON() (data string, err error) {
	var b []byte

	if b, err = json.MarshalIndent(kt, "", "  "); err != nil {
		return "", err
	}

	return string(b), nil
}

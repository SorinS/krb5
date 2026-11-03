package ldap

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// SIDBytes is a SID's binary form (MS-DTYP 2.4.2.2) from its string form
// ("S-1-5-21-...").
func SIDBytes(sid string) ([]byte, error) {
	p := strings.Split(sid, "-")
	if len(p) < 3 || p[0] != "S" || len(p)-3 > 15 {
		return nil, fmt.Errorf("ldap: %q is not a SID", sid)
	}

	rev, err := strconv.ParseUint(p[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("ldap: %q is not a SID", sid)
	}

	auth, err := strconv.ParseUint(p[2], 10, 48)
	if err != nil {
		return nil, fmt.Errorf("ldap: %q is not a SID", sid)
	}

	b := []byte{byte(rev), byte(len(p) - 3), byte(auth >> 40), byte(auth >> 32), byte(auth >> 24), byte(auth >> 16),
		byte(auth >> 8), byte(auth)}

	for _, s := range p[3:] {
		v, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("ldap: %q is not a SID", sid)
		}

		b = binary.LittleEndian.AppendUint32(b, uint32(v))
	}

	return b, nil
}

// SIDString is a binary SID's string form.
func SIDString(b []byte) (string, error) {
	if len(b) < 8 || len(b) != 8+4*int(b[1]) {
		return "", fmt.Errorf("ldap: %d bytes are not a SID", len(b))
	}

	var auth uint64
	for _, c := range b[2:8] {
		auth = auth<<8 | uint64(c)
	}

	s := fmt.Sprintf("S-%d-%d", b[0], auth)
	for i := 0; i < int(b[1]); i++ {
		s += fmt.Sprintf("-%d", binary.LittleEndian.Uint32(b[8+4*i:]))
	}

	return s, nil
}

// DefaultNamingContext reads the root DSE's defaultNamingContext: the
// domain's DN, in Active Directory ("DC=example,DC=com").
func (l *Conn) DefaultNamingContext() (string, error) {
	es, err := l.Search("", ScopeBase, "(objectClass=*)", "defaultNamingContext")
	if err != nil {
		return "", err
	}

	if len(es) != 1 || es[0].Get("defaultNamingContext") == "" {
		return "", fmt.Errorf("ldap: the root DSE has no defaultNamingContext")
	}

	return es[0].Get("defaultNamingContext"), nil
}

// LookupSID finds the entry of a SID (a user's, a group's, a computer's, as
// a PAC gives them) under base: its DN and sAMAccountName.
func (l *Conn) LookupSID(base, sid string) (Entry, error) {
	b, err := SIDBytes(sid)
	if err != nil {
		return Entry{}, err
	}

	es, err := l.Search(base, ScopeSubtree, "(objectSid="+EscapeFilterValue(b)+")", "sAMAccountName", "objectClass", "objectSid")
	if err != nil {
		return Entry{}, err
	}

	if len(es) == 0 {
		return Entry{}, fmt.Errorf("ldap: no entry has SID %s", sid)
	}

	return es[0], nil
}

// TokenGroups returns the SIDs of the groups an entry (a user's DN) is in,
// nested ones too, as the DC computes them (the constructed attribute
// tokenGroups, read with a base search).
func (l *Conn) TokenGroups(dn string) ([]string, error) {
	es, err := l.Search(dn, ScopeBase, "(objectClass=*)", "tokenGroups")
	if err != nil {
		return nil, err
	}

	if len(es) != 1 {
		return nil, fmt.Errorf("ldap: no entry %s", dn)
	}

	var out []string

	for _, v := range es[0].Attributes["tokenGroups"] {
		s, err := SIDString(v)
		if err != nil {
			return nil, err
		}

		out = append(out, s)
	}

	return out, nil
}

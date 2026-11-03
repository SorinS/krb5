package ldap

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// encodeFilter turns a filter's string form (RFC 4515) into its BER (RFC
// 4511 4.5.1.7): and, or, not, equality, presence, substrings, >=, <=,
// approx; values escaped as \XX.
func encodeFilter(s string) ([]byte, error) {
	b, rest, err := parseFilter(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}

	if rest != "" {
		return nil, fmt.Errorf("ldap: filter %q: %q after its end", s, rest)
	}

	return b, nil
}

func parseFilter(s string) ([]byte, string, error) {
	if !strings.HasPrefix(s, "(") {
		return nil, "", fmt.Errorf("ldap: filter %q does not start with (", s)
	}

	s = s[1:]

	switch {
	case strings.HasPrefix(s, "&"), strings.HasPrefix(s, "|"):
		tag := byte(classContext | constructed | 0)
		if s[0] == '|' {
			tag = classContext | constructed | 1
		}

		s = s[1:]

		var parts [][]byte

		for strings.HasPrefix(s, "(") {
			p, rest, err := parseFilter(s)
			if err != nil {
				return nil, "", err
			}

			parts = append(parts, p)
			s = rest
		}

		if !strings.HasPrefix(s, ")") {
			return nil, "", fmt.Errorf("ldap: filter: ) missing")
		}

		return enc(tag, parts...), s[1:], nil
	case strings.HasPrefix(s, "!"):
		p, rest, err := parseFilter(s[1:])
		if err != nil {
			return nil, "", err
		}

		if !strings.HasPrefix(rest, ")") {
			return nil, "", fmt.Errorf("ldap: filter: ) missing")
		}

		return enc(classContext|constructed|2, p), rest[1:], nil
	}

	end := strings.IndexByte(s, ')')
	if end < 0 {
		return nil, "", fmt.Errorf("ldap: filter: ) missing")
	}

	item, rest := s[:end], s[end+1:]

	eq := strings.IndexByte(item, '=')
	if eq <= 0 {
		return nil, "", fmt.Errorf("ldap: filter item %q has no =", item)
	}

	attr, value := item[:eq], item[eq+1:]

	var tag byte = classContext | constructed | 3 // equalityMatch

	switch {
	case strings.HasSuffix(attr, ">"):
		tag, attr = classContext|constructed|5, attr[:len(attr)-1]
	case strings.HasSuffix(attr, "<"):
		tag, attr = classContext|constructed|6, attr[:len(attr)-1]
	case strings.HasSuffix(attr, "~"):
		tag, attr = classContext|constructed|8, attr[:len(attr)-1]
	}

	if tag == classContext|constructed|3 && value == "*" {
		return encOctets(classContext|7, []byte(attr)), rest, nil // present
	}

	if tag == classContext|constructed|3 && strings.Contains(value, "*") {
		parts := strings.Split(value, "*")

		var subs [][]byte

		for i, p := range parts {
			if p == "" {
				continue
			}

			v, err := unescape(p)
			if err != nil {
				return nil, "", err
			}

			t := byte(classContext | 1) // any
			if i == 0 {
				t = classContext | 0 // initial
			} else if i == len(parts)-1 {
				t = classContext | 2 // final
			}

			subs = append(subs, encOctets(t, v))
		}

		return enc(classContext|constructed|4, encOctets(0x04, []byte(attr)), enc(0x30, subs...)), rest, nil
	}

	v, err := unescape(value)
	if err != nil {
		return nil, "", err
	}

	return enc(tag, encOctets(0x04, []byte(attr)), encOctets(0x04, v)), rest, nil
}

// unescape reads a filter value's \XX escapes.
func unescape(s string) ([]byte, error) {
	var out []byte

	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			out = append(out, s[i])
			continue
		}

		if i+2 >= len(s) {
			return nil, fmt.Errorf("ldap: filter value %q: a short escape", s)
		}

		b, err := hex.DecodeString(s[i+1 : i+3])
		if err != nil {
			return nil, fmt.Errorf("ldap: filter value %q: %w", s, err)
		}

		out = append(out, b[0])
		i += 2
	}

	return out, nil
}

// EscapeFilterValue escapes a value for a filter (RFC 4515 3): every byte
// as \XX, which binary values (SIDs, GUIDs) need.
func EscapeFilterValue(v []byte) string {
	var sb strings.Builder

	for _, c := range v {
		fmt.Fprintf(&sb, "\\%02x", c)
	}

	return sb.String()
}

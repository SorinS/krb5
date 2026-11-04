package config

import "testing"

func TestRealmValues(t *testing.T) {
	t.Parallel()

	c, err := NewFromString(`[realms]
    F.TEST = {
        kdc = 127.0.0.1:88
        disable_encrypted_timestamp = true
        pkinit_anchors = FILE:/a.pem
        pkinit_anchors = DIR:/b
        auth_to_local = {
            x = y
        }
    }
`)
	if err != nil {
		t.Fatal(err)
	}

	r := c.Realms[0]
	if !r.DisableEncryptedTimestamp || len(r.Values["pkinit_anchors"]) != 2 || r.Values["pkinit_anchors"][1] != "DIR:/b" {
		t.Errorf("%+v", r)
	}

	if _, ok := r.Values["x"]; ok {
		t.Errorf("a nested relation is the realm's: %+v", r.Values)
	}
}

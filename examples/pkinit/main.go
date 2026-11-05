// Command pkinit gets a TGT with an X.509 certificate instead of a password, or
// anonymously. krb5.conf's pkinit_anchors says which KDC certificates to trust.
//
//	go run ./examples/pkinit -user pat -realm P.TEST -identity FILE:$TEST_MIT_DIR/pki/pat.pem,$TEST_MIT_DIR/pki/pat.key
//	go run ./examples/pkinit -anonymous -realm P.TEST
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/pkinit"
)

func main() {
	user := flag.String("user", "", "the user's name")
	realm := flag.String("realm", "", "the realm")
	spec := flag.String("identity", "", "FILE:cert[,key], as MIT's X509_user_identity")
	anonymous := flag.Bool("anonymous", false, "no identity: an anonymous TGT, of use as FAST's armor")
	flag.Parse()

	cfg, err := config.Load(os.Getenv("KRB5_CONFIG"))
	if err != nil {
		log.Fatal(err)
	}

	var cl *client.Client

	if *anonymous {
		cl = client.NewAnonymous(*realm, cfg)
	} else {
		id, err := pkinit.LoadIdentity(*spec)
		if err != nil {
			log.Fatal(err)
		}

		cl = client.NewWithPKINIT(*user, *realm, id, cfg)
	}

	defer cl.Destroy()

	if err := cl.Login(); err != nil {
		log.Fatal(err)
	}

	c, err := cl.CCache()
	if err != nil {
		log.Fatal(err)
	}

	for _, e := range c.GetEntries() {
		fmt.Printf("TGT for %s@%s\n", e.Client.PrincipalName.PrincipalNameString(), e.Client.Realm)
	}
}

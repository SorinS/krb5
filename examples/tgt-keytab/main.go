// Command tgt-keytab gets a TGT with the keys in a keytab, as a service does.
//
//	go run ./examples/tgt-keytab -keytab $TEST_MIT_DIR/svc.keytab -principal HTTP/svc.a.test -realm A.TEST
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/SorinS/krb5/client"
	"github.com/SorinS/krb5/config"
	"github.com/SorinS/krb5/keytab"
)

func main() {
	ktPath := flag.String("keytab", "", "the keytab file")
	principal := flag.String("principal", "", "the principal, as in the keytab, without the realm")
	realm := flag.String("realm", "", "the realm; empty for krb5.conf's default_realm")
	flag.Parse()

	cfg, err := config.Load(os.Getenv("KRB5_CONFIG"))
	if err != nil {
		log.Fatal(err)
	}

	kt, err := keytab.Load(*ktPath)
	if err != nil {
		log.Fatal(err)
	}

	cl := client.NewWithKeytab(*principal, *realm, kt, cfg)
	defer cl.Destroy()

	if err := cl.Login(); err != nil {
		log.Fatal(err)
	}

	c, err := cl.CCache()
	if err != nil {
		log.Fatal(err)
	}

	for _, e := range c.GetEntries() {
		fmt.Printf("TGT %s for %s@%s until %s\n", e.Server.PrincipalName.PrincipalNameString(),
			e.Client.PrincipalName.PrincipalNameString(), e.Client.Realm, e.EndTime.Format(time.RFC3339))
	}
}

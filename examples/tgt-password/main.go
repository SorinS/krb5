// Command tgt-password gets a TGT with a user's password.
//
//	echo alice-pw | go run ./examples/tgt-password -user alice -realm A.TEST
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/SorinS/krb5/client"
	"github.com/SorinS/krb5/config"
)

func main() {
	user := flag.String("user", "", "the user's name")
	realm := flag.String("realm", "", "the realm; empty for krb5.conf's default_realm")
	flag.Parse()

	// krb5.conf says where the realm's KDCs are and which encryption types
	// to use. config.Load also follows its include and includedir lines.
	cfg, err := config.Load(os.Getenv("KRB5_CONFIG"))
	if err != nil {
		log.Fatal(err)
	}

	// A password is read from stdin, as it should not be on a command line.
	password, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && password == "" {
		log.Fatal("no password on stdin: ", err)
	}

	cl := client.NewWithPassword(*user, *realm, strings.TrimSpace(password), cfg)

	// Destroy forgets the keys and stops the goroutine that renews the TGT.
	defer cl.Destroy()

	// The AS exchange. Pre-authentication (encrypted timestamp, or SPAKE when
	// the KDC offers it), the salt and the KDC's clock are dealt with here.
	if err := cl.Login(); err != nil {
		log.Fatal(err)
	}

	// The TGT is in the client from now on. CCache is the way to look at it.
	c, err := cl.CCache()
	if err != nil {
		log.Fatal(err)
	}

	for _, e := range c.GetEntries() {
		fmt.Printf("TGT %s for %s@%s until %s\n", e.Server.PrincipalName.PrincipalNameString(),
			e.Client.PrincipalName.PrincipalNameString(), e.Client.Realm, e.EndTime.Format(time.RFC3339))
	}
}

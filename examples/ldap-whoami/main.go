// Command ldap-whoami binds to Active Directory's LDAP with Kerberos (SASL
// GSSAPI), encrypting the connection, and reads a user's groups.
//
//	echo $PASSWORD | go run ./examples/ldap-whoami -user alice -realm GOOSE.TEST -ldap 127.0.0.1:3890 -dc dc.goose.test
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/SorinS/krb5/client"
	"github.com/SorinS/krb5/config"
	"github.com/SorinS/krb5/gsskrb5"
	"github.com/SorinS/krb5/ldap"
)

func main() {
	user := flag.String("user", "", "the user's name")
	realm := flag.String("realm", "", "the realm; empty for krb5.conf's default_realm")
	addr := flag.String("ldap", "", "the LDAP server's address")
	dc := flag.String("dc", "", "the DC's host name: its service is ldap/NAME")
	flag.Parse()

	cfg, err := config.Load(os.Getenv("KRB5_CONFIG"))
	if err != nil {
		log.Fatal(err)
	}

	password, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && password == "" {
		log.Fatal("no password on stdin: ", err)
	}

	cl := client.NewWithPassword(*user, *realm, strings.TrimSpace(password), cfg)
	defer cl.Destroy()

	if err := cl.Login(); err != nil {
		log.Fatal(err)
	}

	conn, err := ldap.Dial(*addr)
	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	// The strongest layer the server offers, of those allowed here.
	if err := conn.BindGSSAPI(cl, "ldap@"+*dc, gsskrb5.LayerConfidentiality); err != nil {
		log.Fatal(err)
	}

	who, err := conn.WhoAmI()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("bound as", who)

	base, err := conn.DefaultNamingContext()
	if err != nil {
		log.Fatal(err)
	}

	entries, err := conn.Search(base, ldap.ScopeSubtree, "(sAMAccountName="+*user+")", "distinguishedName")
	if err != nil {
		log.Fatal(err)
	}

	if len(entries) != 1 {
		log.Fatalf("%d entries for %s", len(entries), *user)
	}

	// Every group, nested ones too, as SIDs: AD resolves them here.
	sids, err := conn.TokenGroups(entries[0].DN)
	if err != nil {
		log.Fatal(err)
	}

	for _, sid := range sids {
		group, err := conn.LookupSID(base, sid)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(sid, group.DN)
	}
}

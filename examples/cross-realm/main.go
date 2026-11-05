// Command cross-realm gets a ticket to a service of another realm that trusts
// the user's. Nothing about the trust is in the code: krb5.conf's domain_realm
// says which realm the service is in, the client gets a cross-realm TGT
// (krbtgt/THEIRS@OURS) from its own KDC and takes it to the other realm's.
//
//	echo alice-pw | go run ./examples/cross-realm -user alice -realm A.TEST \
//	    -spn HTTP/svc.b.test -keytab $TEST_MIT_DIR/b.keytab
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/keytab"
)

func main() {
	user := flag.String("user", "", "the user's name")
	realm := flag.String("realm", "", "the user's realm")
	spn := flag.String("spn", "", "a service in the other realm")
	ktPath := flag.String("keytab", "", "the service's keytab, to look in the ticket as it would; optional")
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

	tkt, _, err := cl.GetServiceTicket(*spn)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("ticket to %s@%s\n", tkt.SName.PrincipalNameString(), tkt.Realm)

	// The TGTs the client holds now: its own and the cross-realm one.
	c, err := cl.CCache()
	if err != nil {
		log.Fatal(err)
	}

	for _, e := range c.GetEntries() {
		fmt.Printf("holds %s@%s\n", e.Server.PrincipalName.PrincipalNameString(), e.Server.Realm)
	}

	if *ktPath == "" {
		return
	}

	// What the service sees: the client is of the other realm, and the realms
	// crossed are listed by the KDC. A service decides for itself whom of
	// another realm it lets in.
	kt, err := keytab.Load(*ktPath)
	if err != nil {
		log.Fatal(err)
	}

	if err := tkt.DecryptEncPart(kt, nil); err != nil {
		log.Fatal(err)
	}

	p := tkt.DecryptedEncPart
	fmt.Printf("the service sees %s@%s\n", p.CName.PrincipalNameString(), p.CRealm)
}

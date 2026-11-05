// Command fast logs a user in under FAST armor (RFC 6113): the exchange goes
// inside a tunnel keyed by another TGT, a machine's, so it cannot be captured
// and guessed at offline, and the KDC's errors cannot be forged. F.TEST's KDC
// takes a password no other way.
//
//	echo grace-pw | go run ./examples/fast -user grace -realm F.TEST \
//	    -armor-keytab $TEST_MIT_DIR/fast.keytab -armor-principal host/fast.f.test -spn HTTP/svc.f.test
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
	realm := flag.String("realm", "", "the realm")
	armorKeytab := flag.String("armor-keytab", "", "the machine's keytab")
	armorPrincipal := flag.String("armor-principal", "", "the machine's principal")
	spn := flag.String("spn", "", "a service to get a ticket to")
	flag.Parse()

	cfg, err := config.Load(os.Getenv("KRB5_CONFIG"))
	if err != nil {
		log.Fatal(err)
	}

	kt, err := keytab.Load(*armorKeytab)
	if err != nil {
		log.Fatal(err)
	}

	machine := client.NewWithKeytab(*armorPrincipal, *realm, kt, cfg)
	defer machine.Destroy()

	armor, err := machine.Armor()
	if err != nil {
		log.Fatal(err)
	}

	password, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && password == "" {
		log.Fatal("no password on stdin: ", err)
	}

	cl := client.NewWithPassword(*user, *realm, strings.TrimSpace(password), cfg, client.FASTArmor(armor))
	defer cl.Destroy()

	if err := cl.Login(); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s logged in under armor\n", cl.Credentials.UserName())

	// TGS requests are armored by the TGT itself when the KDC does FAST.
	tkt, _, err := cl.GetServiceTicket(*spn)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("a ticket to", tkt.SName.PrincipalNameString())
}

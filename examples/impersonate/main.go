// Command impersonate is S4U2Self, or protocol transition: a service gets a
// ticket to itself in a user's name, without the user's password. For users who
// authenticated some way other than Kerberos: the service vouches for them,
// and the ticket's PAC gives their groups.
//
//	go run ./examples/impersonate -keytab $TEST_MIT_DIR/s4u.keytab -service HTTP/proxy.a.test -realm A.TEST -user alice
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/SorinS/krb5/client"
	"github.com/SorinS/krb5/config"
	"github.com/SorinS/krb5/iana/flags"
	"github.com/SorinS/krb5/iana/nametype"
	"github.com/SorinS/krb5/keytab"
	"github.com/SorinS/krb5/types"
)

func main() {
	ktPath := flag.String("keytab", "", "the service's keytab")
	service := flag.String("service", "", "the service's principal, as in the keytab")
	realm := flag.String("realm", "", "the realm of the service and the user")
	user := flag.String("user", "", "the user")
	flag.Parse()

	cfg, err := config.Load(os.Getenv("KRB5_CONFIG"))
	if err != nil {
		log.Fatal(err)
	}

	kt, err := keytab.Load(*ktPath)
	if err != nil {
		log.Fatal(err)
	}

	// A forwardable TGT, or the ticket will not be forwardable either.
	cfg.LibDefaults.Forwardable = true

	cl := client.NewWithKeytab(*service, *realm, kt, cfg)
	defer cl.Destroy()

	if err := cl.Login(); err != nil {
		log.Fatal(err)
	}

	tkt, _, err := cl.GetServiceTicketForUser(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, *user), *realm)
	if err != nil {
		log.Fatal(err)
	}

	// The ticket is to the service itself, so it can read it. AD addresses it
	// to the account's name, so that name finds the key.
	self, _ := types.ParseSPNString(*service)
	if err := tkt.DecryptEncPart(kt, &self); err != nil {
		log.Fatal(err)
	}

	p := tkt.DecryptedEncPart
	fmt.Printf("a ticket to %s in the name of %s@%s, forwardable: %v\n", *service, p.CName.PrincipalNameString(), p.CRealm,
		types.IsFlagSet(&p.Flags, flags.Forwardable))

	isPAC, pac, err := tkt.GetPACType(kt, &self, nil)
	if err != nil {
		log.Fatal(err)
	}

	if isPAC && pac.KerbValidationInfo != nil {
		fmt.Println("PAC user:", pac.KerbValidationInfo.EffectiveName.Value, "groups:", pac.KerbValidationInfo.GetGroupMembershipSIDs())
	}
}

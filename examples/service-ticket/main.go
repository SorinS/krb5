// Command service-ticket gets a ticket to a service by its SPN, for a user with
// a password (from stdin) or a keytab, or from a credential cache.
//
//	echo alice-pw | go run ./examples/service-ticket -user alice -spn HTTP/svc.a.test
//	go run ./examples/service-ticket -ccache /tmp/alice.cc -spn HTTP/svc.a.test
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
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/keytab"
)

func main() {
	user := flag.String("user", "", "the user or service")
	realm := flag.String("realm", "", "its realm; empty for krb5.conf's default_realm")
	ktPath := flag.String("keytab", "", "a keytab, in place of a password")
	ccPath := flag.String("ccache", "", "a credential cache, in place of the two")
	spn := flag.String("spn", "", "the service: SERVICE/host.example.com")
	flag.Parse()

	cfg, err := config.Load(os.Getenv("KRB5_CONFIG"))
	if err != nil {
		log.Fatal(err)
	}

	cl, err := newClient(*user, *realm, *ktPath, *ccPath, cfg)
	if err != nil {
		log.Fatal(err)
	}

	defer cl.Destroy()

	// Logs in if it has to (a client from a cache has its TGT), asks the KDC,
	// and keeps the ticket: the next call for this SPN does not ask again.
	tkt, key, err := cl.GetServiceTicket(*spn)
	if err != nil {
		log.Fatal(err)
	}

	// The ticket is sealed with the service's key: the client sends it on and
	// keeps the session key, the secret the two will then share.
	fmt.Printf("ticket to %s@%s, encryption type %d, kvno %d, session key of type %d\n",
		tkt.SName.PrincipalNameString(), tkt.Realm, tkt.EncPart.EType, tkt.EncPart.KVNO, key.KeyType)
}

func newClient(user, realm, ktPath, ccPath string, cfg *config.Config) (*client.Client, error) {
	switch {
	case ccPath != "":
		c, err := credentials.LoadCCache(ccPath)
		if err != nil {
			return nil, err
		}

		return client.NewFromCCache(c, cfg)
	case ktPath != "":
		kt, err := keytab.Load(ktPath)
		if err != nil {
			return nil, err
		}

		return client.NewWithKeytab(user, realm, kt, cfg), nil
	default:
		password, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && password == "" {
			return nil, fmt.Errorf("no password on stdin: %w", err)
		}

		return client.NewWithPassword(user, realm, strings.TrimSpace(password), cfg), nil
	}
}

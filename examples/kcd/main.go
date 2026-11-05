// Command kcd is Kerberos constrained delegation: a front-end service calls a
// back-end service as a user, with S4U2Self (a ticket to itself in the user's
// name) and S4U2Proxy (that ticket for one to the back end). The KDC decides:
// on AD the service's msDS-AllowedToDelegateTo must name the target, and
// TrustedToAuthForDelegation must be set for S4U2Self's ticket to count.
// MIT's DB2 back end refuses S4U2Proxy, so this one takes AD.
//
//	go run ./examples/kcd -keytab proxy.keytab -service svc-proxy -realm GOOSE.TEST \
//	    -user alice -target HTTP/target.goose.test -url http://127.0.0.1:8080/
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/spnego"
	"github.com/go-krb5/krb5/types"
)

func main() {
	ktPath := flag.String("keytab", "", "the front end's keytab")
	service := flag.String("service", "", "the front end's principal, as in the keytab")
	realm := flag.String("realm", "", "the realm")
	user := flag.String("user", "", "the user to act for")
	target := flag.String("target", "", "the back end's SPN")
	url := flag.String("url", "", "the back end's URL, to call it as the user; optional")
	flag.Parse()

	cfg, err := config.Load(os.Getenv("KRB5_CONFIG"))
	if err != nil {
		log.Fatal(err)
	}

	kt, err := keytab.Load(*ktPath)
	if err != nil {
		log.Fatal(err)
	}

	// S4U2Self's ticket must be forwardable for S4U2Proxy, and is only if the
	// service's own TGT is.
	cfg.LibDefaults.Forwardable = true

	cl := client.NewWithKeytab(*service, *realm, kt, cfg)
	defer cl.Destroy()

	if err := cl.Login(); err != nil {
		log.Fatal(err)
	}

	// The evidence. When the user came with a Kerberos ticket to this service,
	// that ticket is the evidence and this step goes.
	evidence, _, err := cl.GetServiceTicketForUser(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, *user), *realm)
	if err != nil {
		log.Fatal("S4U2Self: ", err)
	}

	tkt, key, err := cl.GetServiceTicketForProxy(*target, evidence)
	if err != nil {
		log.Fatal("S4U2Proxy: ", err)
	}

	fmt.Printf("a ticket to %s in the name of %s\n", tkt.SName.PrincipalNameString(), *user)

	if *url == "" {
		return
	}

	header, err := negotiateHeader(*user, *realm, tkt, key)
	if err != nil {
		log.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodGet, *url, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set(spnego.HTTPHeaderAuthRequest, header)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s: %s", resp.Status, body)
}

// negotiateHeader is the Negotiate value for a ticket the service holds in a
// user's name. The authenticator must name the ticket's client, not the
// service, and a Client given only those credentials is what makes it so.
func negotiateHeader(user, realm string, tkt messages.Ticket, key types.EncryptionKey) (string, error) {
	as := &client.Client{Credentials: credentials.New(user, realm)}

	init, err := spnego.NewNegTokenInitKRB5(as, tkt, key)
	if err != nil {
		return "", err
	}

	token := spnego.SPNEGOToken{Init: true, NegTokenInit: init}

	b, err := token.Marshal()
	if err != nil {
		return "", err
	}

	return "Negotiate " + base64.StdEncoding.EncodeToString(b), nil
}

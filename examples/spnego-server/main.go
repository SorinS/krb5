// Command spnego-server is an HTTP server that takes Kerberos (SPNEGO,
// Authorization: Negotiate) with its keys in a keytab, and tells the client
// who it is. With a PAC (AD, MIT 1.20 and later) that includes the groups.
//
//	go run ./examples/spnego-server -keytab $TEST_MIT_DIR/svc.keytab -addr 127.0.0.1:8080
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/go-krb5/x/identity"

	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/service"
	"github.com/go-krb5/krb5/spnego"
)

func main() {
	ktPath := flag.String("keytab", "", "the service's keytab")
	addr := flag.String("addr", "127.0.0.1:8080", "where to listen")
	principal := flag.String("principal", "", "the keytab's principal, when not the one tickets are addressed to (AD: an account's name for its SPN)")
	flag.Parse()

	kt, err := keytab.Load(*ktPath)
	if err != nil {
		log.Fatal(err)
	}

	settings := []func(*service.Settings){service.Logger(log.Default())}
	if *principal != "" {
		settings = append(settings, service.KeytabPrincipal(*principal))
	}

	// The wrapper answers a request without a valid ticket with 401 and
	// WWW-Authenticate: Negotiate. Past it, the request has an identity. Add
	// service.SessionManager to spare a ticket on every request.
	mux := http.NewServeMux()
	mux.Handle("/", spnego.SPNEGOKRB5Authenticate(http.HandlerFunc(whoami), kt, settings...))

	log.Printf("listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func whoami(w http.ResponseWriter, r *http.Request) {
	creds, ok := identity.FromHTTPRequestContext(r).(*credentials.Credentials)
	if !ok {
		http.Error(w, "no identity", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "hello %s@%s\n", creds.UserName(), creds.Domain())

	if _, ok := creds.Attributes()[credentials.AttributeKeyADCredentials]; ok {
		ad := creds.GetADCredentials()
		fmt.Fprintf(w, "logon domain %s, groups %v\n", ad.LogonDomainName, ad.GroupMembershipSIDs)
	}
}

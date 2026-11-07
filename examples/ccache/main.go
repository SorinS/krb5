// Command ccache logs in, saves the tickets to a credential cache and uses them
// from it, without the password. MIT's and Heimdal's klist read the file, and
// a cache from MIT's kinit can be used the same way.
//
//	echo alice-pw | go run ./examples/ccache -user alice -path /tmp/alice.cc -spn HTTP/svc.a.test
//	klist -c /tmp/alice.cc
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/credentials"
)

func main() {
	user := flag.String("user", "", "the user's name")
	realm := flag.String("realm", "", "the realm; empty for krb5.conf's default_realm")
	path := flag.String("path", "", "the credential cache file")
	spn := flag.String("spn", "", "a service to get a ticket to from the cache")
	flag.Parse()

	cfg, err := config.Load(os.Getenv("KRB5_CONFIG"))
	if err != nil {
		printErr( "error loading krb5.conf", err)
		os.Exit(1)
	}

	password, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && password == "" {
		printErr("no password on stdin", err)
		os.Exit(2)
	}

	cl := client.NewWithPassword(*user, *realm, strings.TrimSpace(password), cfg)
	defer cl.Destroy()

	if err := cl.Login(); err != nil {
		printErr("login error", err)
		os.Exit(3)
	}

	// Written with mode 0600, by rename: as kinit does.
	if err := cl.SaveCCache(*path); err != nil {
		printErr("save cache error", err)
		os.Exit(4)
	}

	fmt.Println("saved", *path)

	// A new client, which knows only the file.
	c, err := credentials.LoadCCache(*path)
	if err != nil {
		printErr("error loading ccache", err)
		os.Exit(5)
	}

	fromCache, err := client.NewFromCCache(c, cfg)
	if err != nil {
		printErr( "error loading from ccache", err)
		os.Exit(5)
	}

	defer fromCache.Destroy()

	tkt, _, err := fromCache.GetServiceTicket(*spn)
	if err != nil {
		printErr( "error getting a service ticket", err)
		os.Exit(7)
	}

	fmt.Printf("from the cache, as %s: a ticket to %s\n", fromCache.Credentials.UserName(), tkt.SName.PrincipalNameString())

	// The file again, with the new ticket in it too.
	if err := fromCache.SaveCCache(*path); err != nil {
		printErr("error saving the ccache", err)
		os.Exit(8)
	}
}

func printErr(msg string, err error) {
	_, _ = fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
}

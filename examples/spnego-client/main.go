// Command spnego-client calls a web service that takes Kerberos.
//
//	echo alice-pw | go run ./examples/spnego-client -user alice -spn HTTP/svc.a.test -url http://127.0.0.1:8080/
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/spnego"
)

func main() {
	user := flag.String("user", "", "the user's name")
	realm := flag.String("realm", "", "the realm; empty for krb5.conf's default_realm")
	spn := flag.String("spn", "", "the service; empty for HTTP/ and the URL's host")
	url := flag.String("url", "", "the URL")
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

	// Has the methods of http.Client. A nil http.Client is the default one.
	web := spnego.NewClient(cl, nil, *spn)

	resp, err := web.Get(*url)
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("%s: %s", resp.Status, body)
	}

	fmt.Print(string(body))
}

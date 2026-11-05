// Command keytab-make writes a keytab from a principal's password, with the
// salt MIT and AD's user accounts use by default (REALMname). The kvno must
// be the account's for a service's keytab: service-ticket prints it.
//
//	echo $PASSWORD | go run ./examples/keytab-make -principal svc-proxy -realm GOOSE.TEST -kvno 2 -out proxy.keytab
package main

import (
	"bufio"
	"flag"
	"log"
	"os"
	"strings"
	"time"

	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/keytab"
)

func main() {
	principal := flag.String("principal", "", "the principal, without the realm")
	realm := flag.String("realm", "", "the realm")
	kvno := flag.Uint("kvno", 1, "the key's version")
	out := flag.String("out", "", "the keytab file to write")
	flag.Parse()

	password, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && password == "" {
		log.Fatal("no password on stdin: ", err)
	}

	kt := keytab.New()

	for _, e := range []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96} {
		if err := kt.AddEntry(*principal, *realm, strings.TrimSpace(password), time.Now(), uint8(*kvno), e); err != nil {
			log.Fatal(err)
		}
	}

	// A keytab holds keys: as good as the password, so mode 0600.
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		log.Fatal(err)
	}

	if _, err := kt.Write(f); err != nil {
		log.Fatal(err)
	}

	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
}

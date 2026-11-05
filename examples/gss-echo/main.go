// Command gss-echo is GSS-API without HTTP or SPNEGO: a client and a server on a
// plain TCP connection authenticate each other, then exchange encrypted
// messages. Tokens go length-prefixed here: framing is the protocol's business.
//
//	go run ./examples/gss-echo -listen 127.0.0.1:9000 -keytab $TEST_MIT_DIR/svc.keytab &
//	echo alice-pw | go run ./examples/gss-echo -connect 127.0.0.1:9000 -user alice -spn host/svc.a.test -message hello
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/gsskrb5"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/service"
)

func main() {
	listen := flag.String("listen", "", "be the server, on this address")
	ktPath := flag.String("keytab", "", "server: the keytab")
	connect := flag.String("connect", "", "be the client, of this address")
	user := flag.String("user", "", "client: the user")
	realm := flag.String("realm", "", "client: the realm; empty for krb5.conf's default_realm")
	spn := flag.String("spn", "", "client: the server's SPN")
	message := flag.String("message", "hello", "client: what to send")
	flag.Parse()

	var err error
	if *listen != "" {
		err = serve(*listen, *ktPath)
	} else {
		err = call(*connect, *user, *realm, *spn, *message)
	}

	if err != nil {
		log.Fatal(err)
	}
}

func serve(addr, ktPath string) error {
	kt, err := keytab.Load(ktPath)
	if err != nil {
		return err
	}

	// The settings hold the replay cache: one for all the connections.
	settings := service.NewSettings(kt)

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	log.Printf("listening on %s", addr)

	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}

		go func() {
			defer c.Close()

			if err := echo(c, settings); err != nil {
				log.Print(err)
			}
		}()
	}
}

func echo(c net.Conn, settings *service.Settings) error {
	first, err := readToken(c)
	if err != nil {
		return err
	}

	// The answer proves to the client that this server has the key.
	ctx, answer, err := gsskrb5.Accept(first, settings, gsskrb5.AcceptOptions{})
	if err != nil {
		if answer != nil {
			_ = writeToken(c, answer)
		}

		return err
	}

	if err := writeToken(c, answer); err != nil {
		return err
	}

	log.Printf("%s@%s connected", ctx.Credentials().UserName(), ctx.Credentials().Domain())

	for {
		token, err := readToken(c)
		if err != nil {
			if err == io.EOF {
				return nil
			}

			return err
		}

		// Unwrap checks integrity and the sequence number, and decrypts.
		msg, _, err := ctx.Unwrap(token)
		if err != nil {
			return err
		}

		reply, err := ctx.Wrap(append([]byte("echo: "), msg...), true)
		if err != nil {
			return err
		}

		if err := writeToken(c, reply); err != nil {
			return err
		}
	}
}

func call(addr, user, realm, spn, message string) error {
	cfg, err := config.Load(os.Getenv("KRB5_CONFIG"))
	if err != nil {
		return err
	}

	password, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && password == "" {
		return fmt.Errorf("no password on stdin: %w", err)
	}

	cl := client.NewWithPassword(user, realm, strings.TrimSpace(password), cfg)
	defer cl.Destroy()

	if err := cl.Login(); err != nil {
		return err
	}

	c, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}

	defer c.Close()

	// FlagMutual: the context is not established until the server answers.
	ctx, first, err := gsskrb5.NewInitiator(cl, spn, gsskrb5.InitOptions{Flags: gsskrb5.FlagMutual | gsskrb5.FlagSequence})
	if err != nil {
		return err
	}

	if err := writeToken(c, first); err != nil {
		return err
	}

	answer, err := readToken(c)
	if err != nil {
		return err
	}

	if err := ctx.Continue(answer); err != nil {
		return err
	}

	token, err := ctx.Wrap([]byte(message), true)
	if err != nil {
		return err
	}

	if err := writeToken(c, token); err != nil {
		return err
	}

	token, err = readToken(c)
	if err != nil {
		return err
	}

	reply, encrypted, err := ctx.Unwrap(token)
	if err != nil {
		return err
	}

	fmt.Printf("%s (encrypted: %v)\n", reply, encrypted)

	return nil
}

func writeToken(w io.Writer, token []byte) error {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(token)))
	_, err := w.Write(append(b, token...))

	return err
}

func readToken(r io.Reader) ([]byte, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}

	size := binary.BigEndian.Uint32(n[:])
	if size > 1<<20 {
		return nil, fmt.Errorf("token of %d bytes", size)
	}

	token := make([]byte, size)
	_, err := io.ReadFull(r, token)

	return token, err
}

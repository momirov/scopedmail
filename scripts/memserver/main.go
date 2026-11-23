// Command memserver starts the seeded in-memory IMAP test server and writes a
// matching scopedmail config, for trying the real binary by hand:
//
//	go run ./scripts/memserver -dir /path/to/workdir
//	SCOPEDMAIL_PASSWORD=... scopedmail --config /path/to/workdir/config.toml mailboxes
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/momirov/scopedmail/internal/testserver"
)

func main() {
	dir := flag.String("dir", "", "directory for ca.pem, config.toml and audit.jsonl")
	policyBody := flag.String("policy", `allow = ["Agent", "Agent/*", "INBOX"]
actions = ["mailboxes", "search", "read", "attachment", "flag", "copy", "move", "delete", "append", "create-mailbox"]
trash = "[Gmail]/Trash"`, "TOML body of the [accounts.demo.policy] table")
	flag.Parse()
	if *dir == "" {
		log.Fatal("-dir is required")
	}
	srv, err := testserver.Start(testserver.Options{})
	if err != nil {
		log.Fatal(err)
	}
	defer srv.Close()
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*dir, "ca.pem"), srv.CAPEM, 0o600); err != nil {
		log.Fatal(err)
	}
	cfg := fmt.Sprintf(`default_account = "demo"
audit_log = %q

[accounts.demo]
host = %q
port = %d
username = %q
auth = "password"
password_env = "SCOPEDMAIL_PASSWORD"
tls_ca_file = "ca.pem"

[accounts.demo.policy]
%s
`, filepath.Join(*dir, "audit.jsonl"), srv.Host, srv.Port, testserver.Username, *policyBody)
	if err := os.WriteFile(filepath.Join(*dir, "config.toml"), []byte(cfg), 0o600); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("listening on %s:%d\nconfig: %s\npassword: %s\n", srv.Host, srv.Port, filepath.Join(*dir, "config.toml"), testserver.Password)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
}

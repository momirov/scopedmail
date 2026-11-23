// Package testserver runs an in-memory IMAP server over TLS with seeded
// mailboxes, and records every command a client sends. Tests and the manual
// harness in scripts/ share it.
package testserver

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

const (
	Username = "agent@example.test"
	Password = "s3cret-pw-do-not-log"

	// Body markers let tests prove a message body never reached the audit log.
	AgentBodyMarker   = "AGENT-BODY-MARKER"
	PrivateBodyMarker = "PRIVATE-BODY-MARKER"
	AllMailBodyMarker = "ALLMAIL-BODY-MARKER"
	AttachmentBytes   = "attachment-payload-bytes"
)

type Options struct {
	// StartTLS serves plaintext and upgrades on STARTTLS instead of implicit TLS.
	StartTLS bool
	// Caps overrides the advertised capabilities.
	Caps imap.CapSet
}

type Server struct {
	Host   string
	Port   int
	CAPEM  []byte
	server *imapserver.Server
	ln     net.Listener
	rec    *recorder
	caPool *x509.CertPool

	startTLS bool
}

type recorder struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *recorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.Write(p)
}

func (r *recorder) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.String()
}

func (r *recorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf.Reset()
}

var clientCommand = regexp.MustCompile(`^[A-Za-z0-9]+ ((?:UID )?[A-Z][A-Z.]*)(?: (.*))?$`)

// Commands returns the client commands the server has received, one per entry,
// with the tag removed. Server responses and literals are excluded.
func (s *Server) Commands() []string {
	var out []string
	for _, line := range strings.Split(s.rec.String(), "\r\n") {
		m := clientCommand.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		switch m[1] {
		case "OK", "NO", "BAD":
			continue
		}
		out = append(out, strings.TrimSpace(m[1]+" "+m[2]))
	}
	return out
}

func (s *Server) ResetCommands() { s.rec.Reset() }

func (s *Server) Close() error {
	return s.server.Close()
}

// Client opens an authenticated connection that trusts the server's CA.
func (s *Server) Client() (*imapclient.Client, error) {
	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	opts := &imapclient.Options{TLSConfig: &tls.Config{RootCAs: s.caPool, ServerName: s.Host}}
	dial := imapclient.DialTLS
	if s.startTLS {
		dial = imapclient.DialStartTLS
	}
	c, err := dial(addr, opts)
	if err != nil {
		return nil, err
	}
	if err := c.Login(Username, Password).Wait(); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

type literal struct {
	*bytes.Reader
}

func (l literal) Size() int64 { return int64(l.Reader.Len()) }

func seed(u *imapmemserver.User) error {
	boxes := []string{"INBOX", "Agent", "Agent/Sub", "Private", "[Gmail]/All Mail", "[Gmail]/Trash"}
	for _, b := range boxes {
		if err := u.Create(b, nil); err != nil {
			return err
		}
	}
	add := func(box string, flags []imap.Flag, raw string) error {
		raw = strings.ReplaceAll(raw, "\n", "\r\n")
		_, err := u.Append(box, literal{bytes.NewReader([]byte(raw))}, &imap.AppendOptions{Flags: flags, Time: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)})
		return err
	}
	msgs := []struct {
		box   string
		flags []imap.Flag
		raw   string
	}{
		{"INBOX", nil, plain("inbox-1@example.test", "Alice <alice@example.test>", "Inbox hello", "Inbox body text")},
		{"Agent", nil, plain("agent-1@example.test", "Alice <alice@example.test>", "Agent hello", AgentBodyMarker+" first line")},
		{"Agent", []imap.Flag{imap.FlagSeen}, withAttachment("agent-2@example.test", "Bob <bob@example.test>", "Quarterly report")},
		{"Agent/Sub", nil, plain("sub-1@example.test", "Carol <carol@example.test>", "Sub message", "Sub body text")},
		{"Private", nil, plain("private-1@example.test", "Dave <dave@example.test>", "Secret plans", PrivateBodyMarker+" launch codes")},
		{"[Gmail]/All Mail", nil, plain("allmail-1@example.test", "Eve <eve@example.test>", "Everything", AllMailBodyMarker)},
	}
	for _, m := range msgs {
		if err := add(m.box, m.flags, m.raw); err != nil {
			return err
		}
	}
	return nil
}

func plain(id, from, subject, body string) string {
	return fmt.Sprintf(`Message-ID: <%s>
Date: Sun, 01 Mar 2026 12:00:00 +0000
From: %s
To: Agent <agent@example.test>
Subject: %s
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 7bit

%s
`, id, from, subject, body)
}

func withAttachment(id, from, subject string) string {
	return fmt.Sprintf(`Message-ID: <%s>
Date: Sun, 01 Mar 2026 12:00:00 +0000
From: %s
To: Agent <agent@example.test>
Cc: Carol <carol@example.test>
Subject: %s
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="MIX"

--MIX
Content-Type: multipart/alternative; boundary="ALT"

--ALT
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

Report attached =E2=80=94 see the file.
--ALT
Content-Type: text/html; charset=utf-8

<p>Report attached</p>
--ALT--
--MIX
Content-Type: text/plain; name="report.txt"
Content-Disposition: attachment; filename="report.txt"
Content-Transfer-Encoding: base64

YXR0YWNobWVudC1wYXlsb2FkLWJ5dGVz
--MIX--
`, id, from, subject)
}

func Start(opts Options) (*Server, error) {
	caCert, caKey, caPEM, err := newCA()
	if err != nil {
		return nil, err
	}
	leaf, err := newLeaf(caCert, caKey)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	mem := imapmemserver.New()
	user := imapmemserver.NewUser(Username, Password)
	if err := seed(user); err != nil {
		return nil, err
	}
	mem.AddUser(user)

	caps := opts.Caps
	if caps == nil {
		caps = imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapIMAP4rev2: {}}
	}
	rec := &recorder{}
	tlsConf := &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12}
	srv := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		},
		Caps:        caps,
		TLSConfig:   tlsConf,
		DebugWriter: rec,
		Logger:      discardLogger{},
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	if !opts.StartTLS {
		ln = tls.NewListener(ln, tlsConf)
	}
	go srv.Serve(ln)
	addr := ln.Addr().(*net.TCPAddr)
	return &Server{Host: "127.0.0.1", Port: addr.Port, CAPEM: caPEM, server: srv, ln: ln, rec: rec, caPool: pool, startTLS: opts.StartTLS}, nil
}

type discardLogger struct{}

func (discardLogger) Printf(string, ...interface{}) {}

func newCA() (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "scopedmail test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func newLeaf(ca *x509.Certificate, caKey *ecdsa.PrivateKey) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

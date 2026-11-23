package testserver

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// Delivery is one message the SMTP sink accepted.
type Delivery struct {
	AuthUser string
	From     string
	To       []string
	Data     []byte
}

type SMTPOptions struct {
	// StartTLS serves plaintext and upgrades on STARTTLS instead of implicit TLS.
	StartTLS bool
	// RejectRcpt makes the sink refuse the RCPT TO for these addresses.
	RejectRcpt map[string]bool
}

// SMTPServer is a TLS SMTP sink that requires PLAIN auth as Username/Password
// and records every connection and every accepted message. It has its own CA.
type SMTPServer struct {
	Host  string
	Port  int
	CAPEM []byte

	server *smtp.Server
	mu     sync.Mutex
	conns  int
	got    []Delivery
}

// Connections counts TCP connections accepted, whether or not they sent mail.
func (s *SMTPServer) Connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}

func (s *SMTPServer) Deliveries() []Delivery {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Delivery(nil), s.got...)
}

func (s *SMTPServer) Close() error { return s.server.Close() }

type smtpBackend struct {
	srv  *SMTPServer
	opts SMTPOptions
}

func (b *smtpBackend) NewSession(*smtp.Conn) (smtp.Session, error) {
	return &smtpSession{b: b}, nil
}

type smtpSession struct {
	b    *smtpBackend
	user string
	from string
	to   []string
}

func (s *smtpSession) AuthMechanisms() []string { return []string{sasl.Plain} }

func (s *smtpSession) Auth(string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(_, user, pass string) error {
		if user != Username || pass != Password {
			return errors.New("bad credentials")
		}
		s.user = user
		return nil
	}), nil
}

func (s *smtpSession) Mail(from string, _ *smtp.MailOptions) error {
	if s.user == "" {
		return smtp.ErrAuthRequired
	}
	s.from = from
	return nil
}

func (s *smtpSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	if s.b.opts.RejectRcpt[to] {
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "no such user"}
	}
	s.to = append(s.to, to)
	return nil
}

func (s *smtpSession) Data(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	srv := s.b.srv
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.got = append(srv.got, Delivery{AuthUser: s.user, From: s.from, To: s.to, Data: bytes.Clone(data)})
	return nil
}

func (s *smtpSession) Reset() { s.from, s.to = "", nil }

func (s *smtpSession) Logout() error { return nil }

type countingListener struct {
	net.Listener
	srv *SMTPServer
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.srv.mu.Lock()
		l.srv.conns++
		l.srv.mu.Unlock()
	}
	return c, err
}

func StartSMTP(opts SMTPOptions) (*SMTPServer, error) {
	caCert, caKey, caPEM, err := newCA()
	if err != nil {
		return nil, err
	}
	leaf, err := newLeaf(caCert, caKey)
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12}
	s := &SMTPServer{CAPEM: caPEM, Host: "127.0.0.1"}
	srv := smtp.NewServer(&smtpBackend{srv: s, opts: opts})
	srv.Domain = "localhost"
	srv.TLSConfig = tlsConf
	srv.ReadTimeout, srv.WriteTimeout = 30*time.Second, 30*time.Second
	srv.ErrorLog = discardSMTPLog{}
	s.server = srv

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	var serve net.Listener = countingListener{ln, s}
	if !opts.StartTLS {
		serve = tls.NewListener(serve, tlsConf)
	}
	s.Port = ln.Addr().(*net.TCPAddr).Port
	go srv.Serve(serve)
	return s, nil
}

type discardSMTPLog struct{}

func (discardSMTPLog) Printf(string, ...interface{}) {}
func (discardSMTPLog) Println(...interface{})        {}

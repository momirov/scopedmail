package gate

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/momirov/scopedmail/internal/config"
)

// SendFunc submits one composed message. It dials and authenticates on every
// call, so the gate runs it only after policy has allowed the send.
type SendFunc func(from string, rcpts []string, raw []byte) error

// Outbound is how a Session sends: the From address, which is always the
// account's own, and the way to submit mail.
type Outbound struct {
	From string
	Send SendFunc
}

// SMTPOutbound submits through the account's [smtp] server over TLS, with the
// account's credentials and trust anchor.
func SMTPOutbound(acct config.Account) Outbound {
	return Outbound{
		From: acct.Username,
		Send: func(from string, rcpts []string, raw []byte) error {
			return submit(acct, from, rcpts, raw)
		},
	}
}

func submit(acct config.Account, from string, rcpts []string, raw []byte) error {
	host := acct.SMTP.Host
	tlsConf, err := tlsConfig(acct, host)
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(host, strconv.Itoa(acct.SMTP.Port))
	dial := smtp.DialTLS
	if acct.SMTP.StartTLS {
		dial = smtp.DialStartTLS
	}
	c, err := dial(addr, tlsConf)
	if err != nil {
		return fmt.Errorf("connect %s: %w", addr, err)
	}
	defer c.Close()
	if err := authenticateSMTP(c, acct); err != nil {
		return err
	}
	if err := c.SendMail(from, rcpts, bytes.NewReader(raw)); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	_ = c.Quit()
	return nil
}

func authenticateSMTP(c *smtp.Client, acct config.Account) error {
	ok, mechs := c.Extension("AUTH")
	if !ok {
		return errors.New("smtp server does not offer AUTH")
	}
	var mech sasl.Client
	switch acct.Auth {
	case config.AuthPassword:
		pw, err := secret(acct.PasswordEnv, acct.PasswordCmd)
		if err != nil {
			return fmt.Errorf("password: %w", err)
		}
		mech = sasl.NewPlainClient("", acct.Username, pw)
	case config.AuthOAuth2:
		token, err := secret("", acct.OAuth2TokenCmd)
		if err != nil {
			return fmt.Errorf("oauth2 token: %w", err)
		}
		offered := strings.Fields(strings.ToUpper(mechs))
		switch {
		case slices.Contains(offered, sasl.OAuthBearer):
			mech = sasl.NewOAuthBearerClient(&sasl.OAuthBearerOptions{
				Username: acct.Username, Token: token, Host: acct.SMTP.Host, Port: acct.SMTP.Port,
			})
		case slices.Contains(offered, xoauth2Mech):
			mech = &xoauth2Client{username: acct.Username, token: token}
		default:
			return errors.New("smtp server supports neither OAUTHBEARER nor XOAUTH2")
		}
	default:
		return fmt.Errorf("unknown auth %q", acct.Auth)
	}
	if err := c.Auth(mech); err != nil {
		return fmt.Errorf("smtp authentication failed: %w", err)
	}
	return nil
}

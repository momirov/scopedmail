package gate

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-sasl"

	"github.com/momirov/scopedmail/internal/config"
)

const (
	dialTimeout   = 30 * time.Second
	secretTimeout = 30 * time.Second
)

// Dialer returns the ConnectFunc for an account. TLS is mandatory: implicit TLS
// by default, STARTTLS when configured, and certificate verification is never
// optional.
func Dialer(acct config.Account) ConnectFunc {
	return func() (*imapclient.Client, error) {
		tlsConf, err := tlsConfig(acct, acct.Host)
		if err != nil {
			return nil, err
		}
		opts := &imapclient.Options{
			TLSConfig: tlsConf,
			Dialer:    &net.Dialer{Timeout: dialTimeout},
		}
		addr := net.JoinHostPort(acct.Host, strconv.Itoa(acct.Port))
		dial := imapclient.DialTLS
		if acct.StartTLS {
			dial = imapclient.DialStartTLS
		}
		c, err := dial(addr, opts)
		if err != nil {
			return nil, fmt.Errorf("connect %s: %w", addr, err)
		}
		if err := authenticate(c, acct); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}
}

// tlsConfig verifies the server named host against the system roots, or
// against tls_ca_file alone when the account sets one. IMAP and SMTP share it.
func tlsConfig(acct config.Account, host string) (*tls.Config, error) {
	conf := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if acct.TLSCAFile == "" {
		return conf, nil
	}
	pemBytes, err := os.ReadFile(acct.TLSCAFile)
	if err != nil {
		return nil, fmt.Errorf("tls_ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("tls_ca_file %s contains no certificates", acct.TLSCAFile)
	}
	conf.RootCAs = pool
	return conf, nil
}

func authenticate(c *imapclient.Client, acct config.Account) error {
	switch acct.Auth {
	case config.AuthPassword:
		pw, err := secret(acct.PasswordEnv, acct.PasswordCmd)
		if err != nil {
			return fmt.Errorf("password: %w", err)
		}
		if err := c.Login(acct.Username, pw).Wait(); err != nil {
			return fmt.Errorf("login failed: %w", err)
		}
	case config.AuthOAuth2:
		token, err := secret("", acct.OAuth2TokenCmd)
		if err != nil {
			return fmt.Errorf("oauth2 token: %w", err)
		}
		var mech sasl.Client
		switch caps := c.Caps(); {
		case caps.Has(imap.AuthCap(sasl.OAuthBearer)):
			mech = sasl.NewOAuthBearerClient(&sasl.OAuthBearerOptions{
				Username: acct.Username, Token: token, Host: acct.Host, Port: acct.Port,
			})
		case caps.Has(imap.AuthCap(xoauth2Mech)):
			mech = &xoauth2Client{username: acct.Username, token: token}
		default:
			return errors.New("server supports neither OAUTHBEARER nor XOAUTH2")
		}
		if err := c.Authenticate(mech); err != nil {
			return fmt.Errorf("oauth2 authentication failed: %w", err)
		}
	default:
		return fmt.Errorf("unknown auth %q", acct.Auth)
	}
	return nil
}

// secret reads a credential from the environment or a command. Errors never
// include the command's output, which could be the secret itself.
func secret(envName string, argv []string) (string, error) {
	var out string
	if envName != "" {
		out = os.Getenv(envName)
		if out == "" {
			return "", fmt.Errorf("environment variable %s is empty", envName)
		}
		return out, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), secretTimeout)
	defer cancel()
	env, err := commandEnv()
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = env
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return "", fmt.Errorf("%s exited with %v", argv[0], exit.ProcessState)
		}
		return "", fmt.Errorf("run %s: %w", argv[0], err)
	}
	out = string(bytes.TrimRight(stdout.Bytes(), "\r\n"))
	if out == "" {
		return "", fmt.Errorf("%s printed nothing", argv[0])
	}
	return out, nil
}

// commandPath is the whole $PATH a credential command sees.
const commandPath = "/usr/bin:/bin:/usr/sbin:/sbin"

// commandEnv is the fixed environment for credential commands. Under sudo,
// the caller's variables can survive into scopedmail, so none of them pass
// on. HOME comes from the user database for the effective user, because
// $HOME may still name the caller's home.
func commandEnv() ([]string, error) {
	u, err := effectiveUser()
	if err != nil {
		return nil, fmt.Errorf("look up the current user for a credential command: %w", err)
	}
	return []string{"PATH=" + commandPath, "HOME=" + u.HomeDir}, nil
}

func effectiveUser() (*user.User, error) {
	if uid := os.Geteuid(); uid >= 0 {
		return user.LookupId(strconv.Itoa(uid))
	}
	return user.Current()
}

const xoauth2Mech = "XOAUTH2"

// xoauth2Client is Google's pre-standard OAuth mechanism, still the one some
// Gmail setups advertise.
type xoauth2Client struct{ username, token string }

func (x *xoauth2Client) Start() (string, []byte, error) {
	return xoauth2Mech, []byte("user=" + x.username + "\x01auth=Bearer " + x.token + "\x01\x01"), nil
}

// Next answers the server's JSON error challenge with an empty line, which is
// how the mechanism asks the server to finish with its tagged NO.
func (x *xoauth2Client) Next([]byte) ([]byte, error) { return []byte{}, nil }

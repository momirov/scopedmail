# scopedmail design

scopedmail is a CLI that AI agents call to work with an IMAP mailbox (Gmail first). A configured policy limits which mailboxes (Gmail labels) and which actions the agent can use. Every attempted action, allowed or denied, is appended to a tamper-evident audit log.

## Threat model

- **In scope.** An agent that is buggy, over-eager, or prompt-injected by email content tries to read or change mail outside the allowed labels. scopedmail denies it and records the attempt.
- **Out of scope.** An agent with shell access as the same OS user can read the config and the credential source. For a hard boundary, run scopedmail as a separate OS user (sudo rule or a small wrapper) so the agent can execute it but cannot read its config, credentials, or audit log. The README documents this setup. The wrapper must pin the config as `scopedmail --config PATH -- "$@"`: a repeated `--config` overrides an earlier one, and an agent-chosen config could run any `password_cmd` as the service user. `append --file` and `attachment --out` act on the local file system as the service user, so the README warns about both.

## Core data shapes

### Action registry (`internal/policy`)

One table is the source of truth. Every CLI command maps to exactly one Action. There are no ad hoc checks.

```go
type Action string // "mailboxes", "search", "read", "attachment", "flag", "copy", "move", "delete", "append", "create-mailbox"

type ActionSpec struct {
    Write  bool // mutates server state
    Target bool // takes a destination mailbox that must also pass the allowlist
}

var Actions = map[Action]ActionSpec{ ... }
```

### Policy (`internal/policy`, pure, no IMAP imports)

```go
type Spec struct { Allow, Deny, Actions []string; Trash string } // unparsed, as in config

type Policy struct {
    allow   []Pattern       // default deny
    deny    []Pattern       // evaluated first, wins over allow
    actions map[Action]bool // enabled actions; default = read-only set {mailboxes, search, read, attachment}
    trash   string          // optional; target for delete (sink, never readable unless also allowed)
}

type Pattern struct{ name string; wildcard bool } // exact "Agent", or "Receipts/*" for strict descendants
type Decision struct { Allowed bool; Reason string }

func New(s Spec) (Policy, error)
func (p Policy) Check(a Action, mailbox string, target string) Decision
func (p Policy) MailboxAllowed(name string) bool
func (p Policy) Describe() Description // what `scopedmail policy` prints
```

`Check` tests, in order: the action is registered, the action is enabled, the mailbox is allowed, and for target actions the target is allowed. `create-mailbox` and `append` check their mailbox like any other action.

Rules:
- `INBOX` matches case-insensitively (RFC 3501). Allow rules are otherwise case-sensitive. Deny rules match case-insensitively, because Gmail resolves labels without regard to case and a case-sensitive deny on `Receipts/Tax` would let `receipts/tax` through.
- Mailbox names are validated: no empty, `.`, or `..` segments, no control characters, no `*` or `%`, and no leading or trailing space.
- A pattern is either an exact name or `Prefix/*`, which matches every descendant of `Prefix` and not `Prefix` itself. A bare `*` is rejected at config parse. Granting everything must be spelled out, so `[Gmail]/All Mail` is never allowed by accident.
- The deny list wins. Everything in Gmail's system namespace, `[Gmail]/...` and `[Google Mail]/...` (All Mail, Important, Spam, Trash, Sent Mail, Drafts, Starred, and localized names), is denied unless an allow rule names that folder exactly. A wildcard allow such as `[Gmail]/*` is rejected at config parse. This closes the bypass of reading the allow-label's messages plus everything else through All Mail.
- Write actions with a target (copy, move) need both source and target allowed. Without this rule, copying out of an allowed label into an unrestricted one would launder data.
- `delete` moves to `trash` when trash is configured, using the same path as `move`. Without trash it sets `\Deleted` and runs UID EXPUNGE on those UIDs only. The trash sink skips the target allowlist on purpose.
- `move` uses MOVE when the server has it. Otherwise it COPYs, waits for the COPY to succeed, then sets `\Deleted` and runs UID EXPUNGE on the moved UIDs. It does not use go-imap's built-in fallback, which pipelines COPY and EXPUNGE and can fall back to a bare EXPUNGE. Without MOVE or UIDPLUS, move and delete refuse rather than risk expunging unrelated `\Deleted` messages.
- `flag` refuses `\Deleted`, `\Recent`, and any other backslash flag. It accepts `seen`, `flagged`, `answered`, `draft`, and keywords of `[A-Za-z0-9$_.-]`. Only `delete` removes mail.

Gmail label semantics fall out of plain IMAP. COPY into a label mailbox adds the label. Expunging from a label mailbox removes only that label. The README documents this.

### Gate (`internal/gate`): the single choke point

The CLI never touches the IMAP client directly. `gate.Session` owns the connection, the policy, and the audit writer. Every exported method runs these steps in order: check the policy, perform the action, then append one audit record. A denied action skips the IMAP call and returns a `*DeniedError`. The connection is opened lazily, so a denied action never runs `password_cmd` or dials. Results are returned only after their audit record is written; if that append fails, the gate returns an `*AuditError` (with `Performed` set when a write already happened) and withholds the results. Arguments the gate cannot act on, such as an unsupported flag or a bad part number, return a `*UsageError` before the policy check and are not audited. `Mailboxes()` filters LIST results through `MailboxAllowed`, so the agent never learns the names of disallowed labels.

The session selects mailboxes read-only (EXAMINE) for read actions. Reading a message must not set `\Seen` implicitly. Use `BODY.PEEK`.

### Audit (`internal/audit`)

Append-only JSONL. One record per attempted action, written after the outcome is known:

```go
type Record struct {
    Seq     uint64    `json:"seq"`
    Time    time.Time `json:"time"`
    Account string    `json:"account"`
    Action  string    `json:"action"`
    Mailbox string    `json:"mailbox,omitempty"`
    Target  string    `json:"target,omitempty"`
    UIDs    []uint32  `json:"uids,omitempty"`
    Args    map[string]string `json:"args,omitempty"` // search criteria, flags; never message bodies or credentials
    Outcome string    `json:"outcome"` // "ok" | "denied" | "error"
    Reason  string    `json:"reason,omitempty"`
    Count   int       `json:"count,omitempty"` // results returned
    Prev    string    `json:"prev"`  // hex sha256 of previous record line ("" for seq 1)
    Hash    string    `json:"hash"`  // sha256(prev || canonical JSON of record with hash field empty)
}
```

- The audit log opens before the IMAP connection does. If the log cannot be opened or locked, the command fails closed and nothing reaches the server.
- `prev` hashes the previous line exactly as stored. A record's stored bytes must equal its canonical encoding, so reformatting a line also breaks the chain.
- An exclusive `flock` covers reading the last record and appending the next one, so concurrent agent processes keep the chain linear. This is unix-only behind a build tag (darwin, linux, and the BSDs). Elsewhere, including Windows, the lock is a no-op, documented as a caveat.
- Opening the log takes the lock once and parses the last line. A log that ends in a partial or unreadable record is refused, so nothing is appended to a broken chain.
- `scopedmail audit verify` recomputes the chain, reports the first broken seq, and on success prints `{"ok":true,"records":N,"head":HASH}`. `scopedmail audit tail [-n N]` (default 10) verifies the whole chain, then prints the last N records.
- A hash chain cannot detect records removed from the end. The README tells operators to pin `head` somewhere the agent cannot write.
- File mode is 0600, and a group- or world-writable log is refused.

### Config (`internal/config`), the TOML boundary

Path: `--config` flag, else `$SCOPEDMAIL_CONFIG`, else `$XDG_CONFIG_HOME/scopedmail/config.toml` (`~/.config/...`). Refuse to load a config or audit file that is group- or world-writable, as ssh does.

```toml
default_account = "work"
audit_log = "~/.local/state/scopedmail/audit.jsonl"

[accounts.work]
host = "imap.gmail.com"
port = 993
username = "me@example.com"
auth = "password"              # "password" | "oauth2"
password_cmd = ["security", "find-generic-password", "-s", "scopedmail", "-w"]  # or password_env = "SCOPEDMAIL_PASSWORD"
# oauth2_token_cmd = ["oama", "access", "me@example.com"]   # prints an access token; used with SASL OAUTHBEARER, else XOAUTH2
# tls_ca_file = "ca.pem"       # replaces the system roots, for a private CA; relative to the config file

[accounts.work.policy]
allow = ["Agent", "Receipts/*"]
deny = []
actions = ["mailboxes", "search", "read", "attachment", "flag"]
trash = "[Gmail]/Trash"
```

There are no inline passwords, so a plaintext `password` key is a parse error. Any other unknown key is also a parse error. TLS is always on (port 993 implicit TLS, or STARTTLS on port 143 when `starttls = true`), certificate verification cannot be disabled, and there is no plaintext option. `audit_log` is required and must be absolute or start with `~/`. `auth = "password"` needs exactly one of `password_cmd` and `password_env`; `auth = "oauth2"` needs `oauth2_token_cmd`. Credential commands run without a shell, with a 30-second timeout, and their output never appears in error messages.

## CLI surface

All output is JSON on stdout. Errors go to stderr as `{"error": {"code": "...", "message": "..."}}`, with `code` one of `denied`, `usage`, `config`, `audit`, `audit_broken`, or `error`.
Exit codes: 0 ok, 1 error, 2 usage, 3 denied by policy.

```
scopedmail [--config PATH] [--account NAME] <command>

mailboxes                                   list allowed mailboxes (with message/unseen counts)
search  -m MBOX [--from --to --subject --body --text --since DATE --before DATE --seen|--unseen --flagged --limit N]
                                            -> [{uid, message_id, date, from, to, cc, subject, flags, size}]
read    -m MBOX UID [--raw] [--html]        -> {summary fields..., in_reply_to?, text, html?, raw?, attachments:[{part, filename, type, size}]}
attachment -m MBOX UID --part P --out FILE  write one decoded part to a new file (mode 0600, never overwrites) -> {part, path, bytes}
flag    -m MBOX --add F,.. --remove F,.. UID...   (F: seen, flagged, answered, draft, or a keyword)
copy    -m MBOX --to MBOX UID...            (Gmail: adds label)
move    -m MBOX --to MBOX UID...
delete  -m MBOX UID...
append  -m MBOX --file MSG.eml [--flags draft,seen]   (save a draft or import a message)
create-mailbox NAME
policy                                      print effective policy for the account (agent self-discovery)
audit verify | audit tail [-n N]
```

Write commands print `{"ok":true,"count":N}`, plus `dest_uids` for copy and move and `uid` for append when the server reports them. `search` returns the newest matches first; `--limit` defaults to 50 and accepts 1 to 1000. `read` returns the HTML body without `--html` when the message has no plain-text part.

`policy` and `audit` do not connect to the server. `audit` reads the log but appends nothing to it.

## Testing

- `internal/policy`: table tests for each matching rule, including Gmail system folders, INBOX case, `/*` descendants, and target checks.
- `internal/audit`: write N records, verify passes. Edit a byte, delete a line, or reorder lines, and verify fails at the right seq. A concurrent-append test uses multiple goroutines on separate file handles.
- End to end: `internal/testserver` starts `github.com/emersion/go-imap/v2/imapserver/imapmemserver` in-process on TLS with a generated CA. The binary trusts it through `tls_ca_file`, which is a documented feature for private CAs rather than a test-only hook. Build the real binary and run the commands against seeded mailboxes. `scripts/memserver` starts the same server for manual runs. Assert allowed reads work, denied mailboxes return exit 3, LIST hides disallowed names, and the audit log contains a verifiable record for each attempt.

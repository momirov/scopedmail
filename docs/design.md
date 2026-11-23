# scopedmail design

scopedmail is a CLI that AI agents call to work with an IMAP mailbox (Gmail first). A configured policy limits which mailboxes (Gmail labels) and which actions the agent can use. Every attempted action, allowed or denied, is appended to a tamper-evident audit log.

## Threat model

- **In scope.** An agent that is buggy, over-eager, or prompt-injected by email content tries to read or change mail outside the allowed labels. scopedmail denies it and records the attempt.
- **Out of scope.** An agent with shell access as the same OS user can read the config and the credential source. For a hard boundary, run scopedmail as a separate OS user (sudo rule or a small wrapper) so the agent can execute it but cannot read its config, credentials, or audit log. Document this in the README.

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
type Policy struct {
    allow   []Pattern       // default deny
    deny    []Pattern       // evaluated first, wins over allow
    actions map[Action]bool // enabled actions; default = read-only set {mailboxes, search, read, attachment}
    trash   string          // optional; target for delete (sink, never readable unless also allowed)
}

type Pattern struct{ raw string } // exact "Agent", or "Receipts/*" for strict descendants
type Decision struct { Allowed bool; Reason string }

func (p Policy) Check(a Action, mailbox string, target string) Decision
func (p Policy) MailboxAllowed(name string) bool
```

Rules:
- `INBOX` matches case-insensitively (RFC 3501). Every other name is case-sensitive.
- A pattern is either an exact name or `Prefix/*`, which matches every descendant of `Prefix` and not `Prefix` itself. A bare `*` is rejected at config parse. Granting everything must be spelled out, so `[Gmail]/All Mail` is never allowed by accident.
- The deny list wins. Gmail system folders are denied unless an explicit allow names them: `[Gmail]/All Mail`, `[Gmail]/Important`, `[Gmail]/Spam`, `[Gmail]/Trash`, `[Gmail]/Sent Mail`, `[Gmail]/Drafts`, `[Gmail]/Starred`, and the `[Google Mail]/...` variants. This closes the bypass of reading the allow-label's messages plus everything else through All Mail.
- Write actions with a target (copy, move) need both source and target allowed. Without this rule, copying out of an allowed label into an unrestricted one would launder data.
- `delete` moves to `trash` when trash is configured and the server supports MOVE. Otherwise it sets `\Deleted` and runs UID EXPUNGE on those UIDs only. The trash sink skips the target allowlist on purpose.

Gmail label semantics fall out of plain IMAP. COPY into a label mailbox adds the label. Expunging from a label mailbox removes only that label. The README documents this.

### Gate (`internal/gate`): the single choke point

The CLI never touches the IMAP client directly. `gate.Session` owns the connection, the policy, and the audit writer. Every exported method runs these steps in order: check the policy, perform the action, then append one audit record. A denied action skips the IMAP call and returns a `*DeniedError`. `Mailboxes()` filters LIST results through `MailboxAllowed`, so the agent never learns the names of disallowed labels.

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
- An exclusive `flock` covers reading the last record and appending the next one, so concurrent agent processes keep the chain linear. This is unix-only behind a build tag. On Windows a no-op lock is documented as a caveat.
- `scopedmail audit verify` recomputes the chain and reports the first broken seq. `scopedmail audit tail [-n N]` prints records.
- File mode is 0600.

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
# oauth2_token_cmd = ["gcloud", "auth", "print-access-token"]   # prints an access token; used with SASL OAUTHBEARER/XOAUTH2

[accounts.work.policy]
allow = ["Agent", "Receipts/*"]
deny = []
actions = ["mailboxes", "search", "read", "attachment", "flag"]
trash = "[Gmail]/Trash"
```

There are no inline passwords, so a plaintext `password` key is a parse error. TLS is always on (port 993 implicit TLS, or STARTTLS when `starttls = true`). There is no plaintext option.

## CLI surface

All output is JSON on stdout. Errors go to stderr as `{"error": {"code": "...", "message": "..."}}`.
Exit codes: 0 ok, 1 error, 2 usage, 3 denied by policy.

```
scopedmail [--config PATH] [--account NAME] <command>

mailboxes                                   list allowed mailboxes (with message/unseen counts)
search  -m MBOX [--from --to --subject --body --text --since DATE --before DATE --seen|--unseen --flagged --limit N]
                                            -> [{uid, message_id, date, from, to, cc, subject, flags, size}]
read    -m MBOX UID [--raw] [--html]        -> {headers..., text, html?, attachments:[{part, filename, type, size}]}
attachment -m MBOX UID --part P --out FILE  write one attachment to disk
flag    -m MBOX --add F,.. --remove F,.. UID...   (F: seen, flagged, answered, draft, or a keyword)
copy    -m MBOX --to MBOX UID...            (Gmail: adds label)
move    -m MBOX --to MBOX UID...
delete  -m MBOX UID...
append  -m MBOX --file MSG.eml [--flags draft,seen]   (save a draft or import a message)
create-mailbox NAME
policy                                      print effective policy for the account (agent self-discovery)
audit verify | audit tail [-n N]
```

`policy` and `audit` do not connect to the server. `audit` reads the log but appends nothing to it.

## Testing

- `internal/policy`: table tests for each matching rule, including Gmail system folders, INBOX case, `/*` descendants, and target checks.
- `internal/audit`: write N records, verify passes. Edit a byte, delete a line, or reorder lines, and verify fails at the right seq. A concurrent-append test uses multiple goroutines on separate file handles.
- End to end: start `github.com/emersion/go-imap/v2/imapserver/imapmemserver` in-process on TLS with a self-signed cert. A test-only CA option in config is acceptable if hidden from docs, or the test uses an `insecure_skip_verify` field that only exists in a `_test`-built hook. Build the real binary and run the commands against seeded mailboxes. Assert allowed reads work, denied mailboxes return exit 3, LIST hides disallowed names, and the audit log contains a verifiable record for each attempt.

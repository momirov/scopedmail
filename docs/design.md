# scopedmail design

scopedmail is a CLI that AI agents call to work with an IMAP mailbox (Gmail first) and to send mail over SMTP. A configured policy limits which mailboxes (Gmail labels) and which actions the agent can use, and which addresses it can send to. Every attempted action, allowed or denied, is appended to a tamper-evident audit log.

## Threat model

- **In scope.** An agent that is buggy, over-eager, or prompt-injected by email content tries to read or change mail outside the allowed labels. scopedmail denies it and records the attempt.
- **Out of scope.** An agent with shell access as the same OS user can read the config and the credential source. For a hard boundary, run scopedmail as a separate OS user (sudo rule or a small wrapper) so the agent can execute it but cannot read its config or credentials, and cannot open the audit log file. `audit tail` shows the agent its own account's records. The README documents this setup.
- **What makes the separate-user setup hold.** Three properties close the ways an agent could steer the service user.
  - *The config cannot be replaced.* An agent-chosen config could run any `password_cmd` as the service user. `--config` and `--account` may each appear once and may not be empty, so a wrapper or sudoers rule that pins `--config` cannot be overridden by a second one. `--config` also beats `$SCOPEDMAIL_CONFIG` and `$XDG_CONFIG_HOME`, which scopedmail ignores when the flag is given. The wrapper still passes `--`, so the agent cannot add a global flag at all.
  - *File paths are confined.* `append --file`, `attachment --out`, and the `send` file flags take paths from the agent, and the service user opens them. Without a limit, an agent could mail the service user's `~/.ssh/id_rsa` to an allowed recipient or create files anywhere it can write. Every such path must resolve inside the account's `files_dir`, and unset means every file flag is refused. `internal/agentfs` enforces it.
  - *Sending is bounded by recipients.* `send_to` limits who receives mail. It cannot limit what the mail says, so an agent can still quote any mail it can read to an allowed address.

## Core data shapes

### Action registry (`internal/policy`)

One table is the source of truth. Every CLI command maps to exactly one Action. There are no ad hoc checks.

```go
type Action string // "mailboxes", "search", "read", "attachment", "flag", "copy", "move", "delete", "append", "create-mailbox", "send"

type ActionSpec struct {
    Write      bool // mutates server state or sends mail
    Target     bool // takes a destination mailbox that must also pass the allowlist
    Recipients bool // addresses outside people: judged against send_to, not a mailbox
}

var Actions = map[Action]ActionSpec{ ... }
```

### Policy (`internal/policy`, pure, no IMAP imports)

```go
type Spec struct {
    Allow, Deny, Actions []string
    Trash                string
    SendTo               []string // addresses and "@domain" rules
    MaxRecipients        int      // 0 means DefaultMaxRecipients (10); at most 100
} // unparsed, as in config

type Policy struct {
    allow         []Pattern          // default deny
    deny          []Pattern          // evaluated first, wins over allow
    actions       map[Action]bool    // enabled actions; default = read-only set {mailboxes, search, read, attachment}
    trash         string             // optional; target for delete (sink, never readable unless also allowed)
    sendTo        []RecipientPattern // required when "send" is enabled
    maxRecipients int
}

type Pattern struct{ name string; wildcard bool } // exact "Agent", or "Receipts/*" for strict descendants
type RecipientPattern struct{ addr, domain string } // exact "bob@example.com", or "@example.com"
type Decision struct { Allowed bool; Reason string }

func New(s Spec) (Policy, error)
func (p Policy) Check(a Action, mailbox string, target string) Decision
func (p Policy) CheckSend(recipients []string) Decision
func (p Policy) MailboxAllowed(name string) bool
func (p Policy) Describe() Description // what `scopedmail policy` prints
```

`Check` tests, in order: the action is registered, the action is enabled, the mailbox is allowed, and for target actions the target is allowed. `create-mailbox` and `append` check their mailbox like any other action. `Check` refuses an action with `Recipients` set, because that action goes through `CheckSend`.

Rules:
- `INBOX` matches case-insensitively (RFC 3501). Allow rules are otherwise case-sensitive. Deny rules match case-insensitively, because Gmail resolves labels without regard to case and a case-sensitive deny on `Receipts/Tax` would let `receipts/tax` through.
- Mailbox names are validated: no empty, `.`, or `..` segments, no control characters, no `*` or `%`, and no leading or trailing space.
- A pattern is either an exact name or `Prefix/*`, which matches every descendant of `Prefix` and not `Prefix` itself. A bare `*` is rejected at config parse. Granting everything must be spelled out, so `[Gmail]/All Mail` is never allowed by accident.
- The deny list wins. Everything in Gmail's system namespace, `[Gmail]/...` and `[Google Mail]/...` (All Mail, Important, Spam, Trash, Sent Mail, Drafts, Starred, and localized names), is denied unless an allow rule names that folder exactly. A wildcard allow such as `[Gmail]/*` is rejected at config parse. This closes the bypass of reading the allow-label's messages plus everything else through All Mail.
- Write actions with a target (copy, move) need both source and target allowed. Without this rule, copying out of an allowed label into an unrestricted one would launder data.
- `delete` moves to `trash` when trash is configured, using the same path as `move`. Without trash it sets `\Deleted` and runs UID EXPUNGE on those UIDs only. The trash sink skips the target allowlist on purpose.
- `move` uses MOVE when the server has it. Otherwise it COPYs, waits for the COPY to succeed, then sets `\Deleted` and runs UID EXPUNGE on the moved UIDs. It does not use go-imap's built-in fallback, which pipelines COPY and EXPUNGE and can fall back to a bare EXPUNGE. Without MOVE or UIDPLUS, move and delete refuse rather than risk expunging unrelated `\Deleted` messages.
- `send` is enabled only with a non-empty `send_to`, and `New` rejects the spec otherwise. `CheckSend` takes every To, Cc, and Bcc address. Each must be a plain ASCII addr-spec with an unquoted local part (letters, digits, dots, and `_-+'`), and must match an exact address or an `@domain` rule. A domain rule matches that domain only, not its subdomains. Matching ignores case. One failing address denies the whole send and the reason names it. The count of distinct addresses may not exceed `max_recipients`. Quoted local parts, comments, IP literals, and non-ASCII are rejected because they are how an allowlist gets confused about the real domain.
- `flag` refuses `\Deleted`, `\Recent`, and any other backslash flag. It accepts `seen`, `flagged`, `answered`, `draft`, and keywords of `[A-Za-z0-9$_.-]`. Only `delete` removes mail.

Gmail label semantics fall out of plain IMAP. COPY into a label mailbox adds the label. Expunging from a label mailbox removes only that label. The README documents this.

### Gate (`internal/gate`): the single choke point

The CLI never touches the IMAP client directly. `gate.Session` owns the connection, the policy, and the audit writer. Every exported method runs these steps in order: check the policy, append an intent record for a write, perform the action, then append the outcome record. A denied action skips the IMAP call and returns a `*DeniedError`. For `send`, the decision covers every recipient, and a reply's mailbox also has to pass the read policy. The connection is opened lazily, so a denied action never runs `password_cmd` or dials. A write (every action with `Write` in the registry, `send` included) first appends a record with outcome `started` and its arguments, and `Append` syncs it to disk. If that append fails, the gate returns an `*AuditError` and makes no network call. The outcome record then names the intent in `intent_seq`. So a failed append, a kill, or a crash after the intent leaves an unfinished intent, never a change with no record. A read appends only its outcome record. Results are returned only after that record is written. If the outcome append fails, the gate returns an `*AuditError` (with `Performed` set when a write already happened) and withholds the results, and it removes a file that `attachment` wrote. Arguments the gate cannot act on, such as an unsupported flag or a bad part number, return a `*UsageError` before the policy check and are not audited. `Mailboxes()` filters LIST results through `MailboxAllowed`, so the agent never learns the names of disallowed labels.

Two methods share the choke point without being IMAP actions:

- `Send` builds the message, then asks `audited` to check the recipients, submit over SMTP (`Outbound`, set from the account's `[smtp]` table), and record the result. It opens an IMAP connection only for a reply, to read the original's headers with EXAMINE and PEEK. The From address is the account's `username` and no header comes from the agent. Bcc goes into the envelope only. The record holds recipients, attachment names and sizes, and hashes of the subject and of the message, never the text.
- `OpenFile(action, path)` is how the CLI opens a path the agent supplied for `send` and `append`. It asks `agentfs.Dir` to open it. A refused path writes a `denied` record, with the path in `args["file"]`, before the error returns. `attachment` creates its file inside the audited action. A `*agentfs.Denied` raised there becomes a `*DeniedError` and a `denied` record, and the policy check calls `Dir.Check` first, so with `files_dir` unset the command is denied before it connects.

`read --raw` fetches `BODY.PEEK[]`. When the server returns an empty source for a message whose `RFC822.SIZE` is not zero, `Read` returns an error and the record has outcome `error`. `Message.Raw` is a pointer, so a raw read always carries the key. go-imap's in-memory server returns an empty literal for a message whose headers do not parse, which is how this showed up.

The session selects mailboxes read-only (EXAMINE) for read actions. Reading a message must not set `\Seen` implicitly. Use `BODY.PEEK`.

### File paths (`internal/agentfs`)

`agentfs.Dir` is the only code that opens a path chosen by the agent. It holds the configured `files_dir`, opens an `*os.Root` on it lazily, and offers `Open` (regular files, read), `Create` (`O_EXCL`, mode 0600), `Remove`, `Check`, and `Rel`. An empty `files_dir` makes an off `Dir`, which returns `*Denied` for every path.

- A relative path is relative to `files_dir`. An absolute path must lie lexically inside it, under its configured name or its symlink-resolved name, and `Rel` turns it into a relative name.
- That name goes to `os.Root`. Root resolves it component by component without following a symlink out of the directory, so a `..` climb, a symlinked directory, a symlink to an outside file, and a symlink swapped mid-run all fail inside the open. The check and the open are one system call sequence, so no gap exists between them. `Rel` and `Check` only choose a name and give an early denial. They are not the boundary.
- `os.Root` exports no sentinel for an escape, so `escaped` matches the text `path escapes from parent` and maps it to `*Denied`. An error it misses is still an error, and the open still failed.
- `Open` opens with `O_NONBLOCK`, so a FIFO cannot block it, and then checks the open handle with `fstat`. The handle must be a regular file with exactly one link. A stat of the name before the open would leave a window in which a FIFO could be swapped in. A hard link to a file outside passes every `os.Root` check, because it is the outside file under an inside name, so the link count is the only signal. It is a `*Denied`. Windows reports no link count, so the check is skipped there. The README tells operators to keep `files_dir` on a file system without the service user's secrets, or to rely on `fs.protected_hardlinks=1`.
- `Create` never replaces. An existing file or a symlink at the name gives `file exists`.
- `config.Load` rejects a `files_dir` that is not absolute, or that holds the config file or the audit log, directly or through a symlink.

### Quote stripping (`internal/quote`)

Pure functions: `StripText`, `StripHTML`, and `IsForwardSubject`. `gate.Read` calls them on each decoded text and html part unless `--keep-quotes` is set, `--raw` is set, or the subject starts with `Fwd`, `FW`, `WG`, `TR`, `RV`, or `ENC` followed by a colon. Outlook writes the same header block for a reply and a forward, so a forward subject disables stripping.

- Text. Detectors in `tailDetectors` recognize an attribution line (English, German, French, Spanish, Italian, Dutch, Portuguese, Serbian or Croatian, each with a digit-or-`@` check), Outlook's original-message line, and Outlook's `From`, `Sent`, `To`, `Subject` block in English, German, and French. A marker cuts itself and everything after it, but not when no text of the author's precedes it, and not when a `>` run follows it and the author's text follows that run. Runs of `>` lines become `[… N quoted lines removed]`, or disappear at the end of the body. A line `-- ` drops the rest. A forwarded-message marker and everything after it is kept.
- HTML. `htmlRules` cut elements by client markup: Outlook (`appendonsend`, `divRplyFwdMsg`, the Word border header, each cutting to the end of the body), Gmail, Apple Mail and generic `blockquote type=cite`, Thunderbird, and Yahoo. `htmlKeepers` protect forwards.
- A body that stripping would leave empty comes back unchanged. A body over `quote.MaxBytes` (2 MiB) also comes back unchanged, with `TooLarge` set. `gate.Read` checks every part first, and when one is over the limit it strips none and sets `quotes_skipped` to `"too large"` instead of `quotes_removed`.
- Every step is linear in the body. After tokenizing, one pass stores on each token the index of the end tag that closes it (one stack per tag name), whether it is visible text, the next visible text token, and a running count of visible text tokens that are not blank. Finding an element's end, reading an element's first words, and asking whether a region holds visible text are then lookups, and `leadingText` reads only the element's own tokens. Before this, each candidate element rescanned the rest of the document, and a 1.9 MB message of unclosed quote elements took 15 seconds of CPU. `Result` counts the removed bytes and lines of the original, and `gate.Read` sums both parts into `quotes_removed`.
- The known cost is false positives. Outlook has no `>` prefix, so the cut from its header to the end also removes inline answers typed between the quoted lines. `--keep-quotes` is the escape hatch, and the audit record notes it as `keep_quotes=true`.

### Audit (`internal/audit`)

Append-only JSONL. A read or a denial writes one record after the outcome is known. A write that passes the policy writes two: an intent with outcome `started` before it runs, and its outcome after.

```go
type Record struct {
    Seq     uint64    `json:"seq"`
    Time    time.Time `json:"time"`
    Account string    `json:"account"`
    Action  string    `json:"action"`
    Mailbox string    `json:"mailbox,omitempty"`
    Target  string    `json:"target,omitempty"`
    UIDs    []uint32  `json:"uids,omitempty"`
    Args    map[string]string `json:"args,omitempty"` // search criteria, flags, send recipients and hashes; never message bodies or credentials
    Outcome string    `json:"outcome"` // "ok" | "denied" | "error" | "started"
    Reason  string    `json:"reason,omitempty"`
    Count   int       `json:"count,omitempty"` // results returned
    IntentSeq uint64  `json:"intent_seq,omitempty"` // on an outcome: the seq of its "started" intent
    Prev    string    `json:"prev"`  // hex sha256 of previous record line ("" for seq 1)
    Hash    string    `json:"hash"`  // sha256(prev || canonical JSON of record with hash field empty)
}
```

- The audit log opens before the IMAP connection does. If the log cannot be opened or locked, the command fails closed and nothing reaches the server.
- `RLIMIT_FSIZE` is inherited through `sudo`, so the caller can set it to the log's size and make every append fail with `EFBIG`. On unix, `Open` raises the soft limit to the hard limit, and refuses the log when the hard limit is less than 1 MiB past its end. The Go runtime ignores `SIGXFSZ`, so an append at the limit returns an error and does not kill the process.
- `intent_seq` is `omitempty`, so a record written before intents existed keeps its bytes and its hash. Logs from earlier builds verify unchanged.
- `prev` hashes the previous line exactly as stored. A record's stored bytes must equal its canonical encoding, so reformatting a line also breaks the chain.
- An exclusive `flock` covers reading the last record and appending the next one, so concurrent agent processes keep the chain linear. This is unix-only behind a build tag (darwin, linux, and the BSDs). Elsewhere, including Windows, the lock is a no-op, documented as a caveat.
- Opening the log takes the lock once and parses the last line. A log that ends in a partial or unreadable record is refused, so nothing is appended to a broken chain.
- `scopedmail audit verify` recomputes the chain, reports the first broken seq, and on success prints `{"ok":true,"records":N,"head":HASH,"unfinished":[SEQ...]}`. An outcome must name an earlier unfinished intent of the same account and action, or the chain is broken at the outcome. `unfinished` lists the intents that no outcome closed. A crash leaves one, so verification still passes, and the operator checks the server for that action. `scopedmail audit tail [-n N]` (default 10) verifies the whole chain, then prints the last N records of the selected account. Accounts can share a log, and an agent behind a wrapper pinned to one account must not read another's records. `verify` covers every account and prints only totals.
- A hash chain cannot detect records removed from the end. The README tells operators to pin `head` somewhere the agent cannot write.
- File mode is 0600, and a group- or world-writable log is refused.

### Config (`internal/config`), the TOML boundary

Path: `--config` flag, else `$SCOPEDMAIL_CONFIG`, else `$XDG_CONFIG_HOME/scopedmail/config.toml` (`~/.config/...`). The flag wins over the environment, and a repeated or empty `--config` or `--account` is a usage error (a `flag.Value` that accepts one non-empty value). Refuse to load a config or audit file that is group- or world-writable, as ssh does.

```toml
default_account = "work"
audit_log = "~/.local/state/scopedmail/audit.jsonl"

[accounts.work]
host = "imap.gmail.com"
port = 993
username = "me@example.com"
auth = "password"              # "password" | "oauth2"
password_cmd = ["/usr/bin/security", "find-generic-password", "-s", "scopedmail", "-w"]  # or password_env = "SCOPEDMAIL_PASSWORD"
# oauth2_token_cmd = ["/usr/local/bin/oama", "access", "me@example.com"]   # prints an access token; used with SASL OAUTHBEARER, else XOAUTH2
# tls_ca_file = "ca.pem"       # replaces the system roots, for a private CA; relative to the config file
files_dir = "~/scopedmail-files"  # the only directory agent file paths may use; unset means file flags are refused

[accounts.work.policy]
allow = ["Agent", "Receipts/*"]
deny = []
actions = ["mailboxes", "search", "read", "attachment", "flag", "send"]
trash = "[Gmail]/Trash"
send_to = ["partner@example.com", "@example.org"]   # required with "send"
max_recipients = 10                                  # default 10, at most 100

[accounts.work.smtp]           # optional with Gmail; required with another host once "send" is enabled
host = "smtp.example.net"      # defaults to smtp.gmail.com when host is imap.gmail.com
port = 587                     # 465 implicit TLS by default, 587 with starttls
starttls = true
```

There are no inline passwords, so a plaintext `password` key is a parse error. Any other unknown key is also a parse error. TLS is always on (port 993 implicit TLS, or STARTTLS on port 143 when `starttls = true`), certificate verification cannot be disabled, and there is no plaintext option. `audit_log` is required and must be absolute or start with `~/`. `files_dir` must be absolute or start with `~/`. With `send` enabled, `username` must be a plain email address because it is the From address, and the SMTP server shares the account's credentials and `tls_ca_file`, with TLS always on. `auth = "password"` needs exactly one of `password_cmd` and `password_env`; `auth = "oauth2"` needs `oauth2_token_cmd`. Credential commands run without a shell, with a 30-second timeout, and their output never appears in error messages. The program must be an absolute path, because a bare name would be looked up in a `$PATH` that `sudo` may keep from the agent. The command gets a fixed environment, `PATH=/usr/bin:/bin:/usr/sbin:/sbin` and `HOME` from the user database for the effective user, so no variable the caller set reaches it.

## CLI surface

All output is JSON on stdout. Errors go to stderr as `{"error": {"code": "...", "message": "..."}}`, with `code` one of `denied`, `usage`, `config`, `audit`, `audit_broken`, or `error`. A file path outside `files_dir` is a `denied`, not a `usage` error.
Exit codes: 0 ok, 1 error, 2 usage, 3 denied by policy.

```
scopedmail [--config PATH] [--account NAME] <command>

mailboxes                                   list allowed mailboxes (with message/unseen counts)
search  -m MBOX [--from --to --subject --body --text --since DATE --before DATE --seen|--unseen --flagged --limit N]
                                            -> [{uid, message_id, date, from, to, cc, subject, flags, size}]
read    -m MBOX UID [--raw] [--html] [--keep-quotes]
                                            -> {summary fields..., in_reply_to?, text, html?, raw?, attachments:[{part, filename, type, size}], quotes_removed?:{bytes, lines}, quotes_skipped?:"too large"}
attachment -m MBOX UID --part P --out FILE  write one decoded part to a new file inside files_dir (mode 0600, never overwrites) -> {part, path, bytes}
flag    -m MBOX --add F,.. --remove F,.. UID...   (F: seen, flagged, answered, draft, or a keyword)
copy    -m MBOX --to MBOX UID...            (Gmail: adds label)
move    -m MBOX --to MBOX UID...
delete  -m MBOX UID...
append  -m MBOX --file MSG.eml [--flags draft,seen]   (save a draft or import a message; the file must be inside files_dir)
create-mailbox NAME
send    --to A[,B] [--cc ..] [--bcc ..] [--subject S] (--body S | --body-file F | stdin)
        [--html-file F] [--attach FILE]... [--reply-to -m MBOX UID]
                                            -> {ok, message_id, recipients}
policy                                      print effective policy and files_dir for the account (agent self-discovery)
audit verify | audit tail [-n N]
```

Write commands print `{"ok":true,"count":N}` from one struct, plus `dest_uids` for copy and move and `uid` for append when the server reports them. `search` returns the newest matches first; `--limit` defaults to 50 and accepts 1 to 1000. `read` returns the HTML body without `--html` when the message has no plain-text part. `send` reads files and stdin before it connects, and a reply connects only to read the original's headers.

`policy` prints `{"account", "policy", "files_dir"}`, with `files_dir` null when file paths are off. `policy` and `audit` do not connect to the server. `audit` reads the log but appends nothing to it.

## Testing

- `internal/policy`: table tests for each matching rule, including Gmail system folders, INBOX case, `/*` descendants, and target checks.
- `internal/audit`: write N records, verify passes. Edit a byte, delete a line, or reorder lines, and verify fails at the right seq. A concurrent-append test uses multiple goroutines on separate file handles.
- `internal/agentfs`: every escape (`..`, absolute path, symlink to a file, symlinked directory, dangling symlink on create) is denied for open and create, writes nothing outside, and a goroutine that flips a symlink between an inside and an outside directory never makes a read return the outside content. The same flip run against a check-then-open implementation leaks repeatedly in the same window.
- `internal/cli`: the same escapes against the real binary for `append`, `attachment`, and the three `send` file flags, with files off, with a repeated global flag, and with the flag and the environment in conflict. `internal/quote` has table tests for each detector and rule.
- End to end: `internal/testserver` starts `github.com/emersion/go-imap/v2/imapserver/imapmemserver` in-process on TLS with a generated CA. The binary trusts it through `tls_ca_file`, which is a documented feature for private CAs rather than a test-only hook. Build the real binary and run the commands against seeded mailboxes. `scripts/memserver` starts the same server, an SMTP sink, and a config with `files_dir` for manual runs. The sink in `internal/testserver` records each delivery's envelope and data. Assert allowed reads work, denied mailboxes return exit 3, LIST hides disallowed names, and the audit log contains a verifiable record for each attempt.

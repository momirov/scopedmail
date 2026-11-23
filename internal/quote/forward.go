package quote

import "regexp"

// forwardStart matches the first words of a forwarded message. Forwarded
// content is new information for the reader, so nothing from here on is
// treated as quoted history.
var forwardStart = regexp.MustCompile(`(?i)^(?:` +
	`-{3,} ?(?:forwarded message|forwarded|weitergeleitete nachricht|message transféré|mensaje reenviado|messaggio inoltrato|doorgestuurd bericht|mensagem encaminhada|prosleđena poruka|proslijeđena poruka) ?-{3,}` +
	`|(?:begin forwarded message|anfang der weitergeleiteten nachricht|début du message réexpédié|inicio del mensaje reenviado|inizio messaggio inoltrato|begin doorgestuurd bericht|início da mensagem reencaminhada) ?:)`)

// forwardSubject matches the subject prefixes mail clients put on a forward.
var forwardSubject = regexp.MustCompile(`(?i)^\s*(?:fwd?|wg|tr|rv|enc)\s*:`)

// IsForwardSubject reports whether a subject line marks a forwarded message.
// Outlook writes the same header block for a reply and a forward, so a caller
// that knows the subject should skip stripping a forward.
func IsForwardSubject(subject string) bool { return forwardSubject.MatchString(subject) }

package quote

import (
	"fmt"
	"regexp"
	"strings"
)

// A detector recognises where quoted history begins. match reports how many
// lines the marker spans at lines[i], or 0 when there is no marker there.
// Everything from a marker to the end of the body is quoted history.
//
// Supporting another mail client or language is one more row in tailDetectors.
type detector struct {
	name  string
	match func(lines []string, i int) int
}

var tailDetectors = []detector{
	attribution("en", `^On .+ wrote ?:$`),
	attribution("de", `^Am .+ schrieb.*:$`),
	attribution("fr", `^Le .+ a écrit ?:$`),
	attribution("es", `^El .+ escribió ?:$`),
	attribution("it", `^Il .+ ha scritto ?:$`),
	attribution("nl", `^Op .+ schreef.*:$`),
	attribution("pt", `^Em .+ escreveu ?:$`),
	attribution("sr-hr", `(?:je napisao(?:/la|la)?|napisao(?:/la)? je|je napisala|napisala je|је написао(?:/ла|ла)?|написао(?:/ла)? је|је написала|написала је) ?:$`),
	{"outlook-original-message", originalMessage},
	headerBlock("outlook-en", `From`, `Sent|Date`, `To|Subject`),
	headerBlock("outlook-de", `Von`, `Gesendet|Datum`, `An|Betreff`),
	headerBlock("outlook-fr", `De`, `Envoyé|Date`, `À|Objet`),
}

var originalMessageLine = regexp.MustCompile(`(?i)^-{2,} ?(?:original message|ursprüngliche nachricht|message d'origine|mensaje original|messaggio originale|oorspronkelijk bericht|mensagem original|originalna poruka) ?-{2,}$`)

func originalMessage(lines []string, i int) int {
	if originalMessageLine.MatchString(normalize(lines[i])) {
		return 1
	}
	return 0
}

const (
	maxAttributionLen = 300
	maxWrapLineLen    = 80
	headerLookahead   = 5
)

// attribution matches "On <date>, <name> wrote:". Mail clients wrap a long one
// onto a second line, so the pattern is tried on the line and then on the line
// joined with the next. A digit or an "@" must appear in it, which a sentence
// of prose seldom has and a date or an address always has.
func attribution(name, pattern string) detector {
	re := regexp.MustCompile(pattern)
	ok := func(s string) bool {
		return len(s) <= maxAttributionLen && re.MatchString(s) && strings.ContainsAny(s, "0123456789@")
	}
	return detector{name, func(lines []string, i int) int {
		first := normalize(lines[i])
		if ok(first) {
			return 1
		}
		if i+1 < len(lines) {
			second := normalize(lines[i+1])
			if len(second) <= maxWrapLineLen && ok(first+" "+second) {
				return 2
			}
		}
		return 0
	}}
}

// outlookRule is the line of underscores Outlook on the web draws above the
// header block.
var outlookRule = regexp.MustCompile(`^_{10,}$`)

// headerBlock matches Outlook's "From: ... Sent: ... To: ... Subject: ..."
// block that stands in for an attribution. The first line starts with the from
// field and the next few lines carry a date field and a recipient or subject
// field. A rule of underscores above the block belongs to it.
func headerBlock(name, from, when, whom string) detector {
	fromRe := regexp.MustCompile(`(?i)^(?:` + from + `) ?:\s*\S`)
	whenRe := regexp.MustCompile(`(?i)^(?:` + when + `) ?:`)
	whomRe := regexp.MustCompile(`(?i)^(?:` + whom + `) ?:`)
	return detector{name, func(lines []string, i int) int {
		skip := 0
		if outlookRule.MatchString(normalize(lines[i])) && i+1 < len(lines) {
			skip = 1
		}
		i += skip
		if !fromRe.MatchString(normalize(lines[i])) {
			return 0
		}
		var hasWhen, hasWhom bool
		for j := i + 1; j < len(lines) && j <= i+headerLookahead; j++ {
			l := normalize(lines[j])
			hasWhen = hasWhen || whenRe.MatchString(l)
			hasWhom = hasWhom || whomRe.MatchString(l)
		}
		if hasWhen && hasWhom {
			return 1 + skip
		}
		return 0
	}}
}

// normalize makes a line comparable. French puts a no-break space before the
// colon, and lines of a CRLF body end in a carriage return.
func normalize(line string) string {
	return strings.TrimSpace(strings.NewReplacer(" ", " ", " ", " ").Replace(line))
}

func isBlank(line string) bool { return strings.TrimSpace(line) == "" }

// isQuoted reports whether a line carries the ">" prefix mail clients put on
// quoted text.
func isQuoted(line string) bool {
	return strings.HasPrefix(strings.TrimLeft(line, " \t"), ">")
}

// isSignatureDelimiter is the RFC 3676 delimiter: dash, dash, space.
func isSignatureDelimiter(line string) bool {
	return strings.TrimSuffix(line, "\r") == "-- "
}

func tailMarker(lines []string, i int) int {
	for _, d := range tailDetectors {
		if n := d.match(lines, i); n > 0 {
			return n
		}
	}
	return 0
}

// nextNonBlank returns the index of the first non-blank line at or after i,
// or len(lines).
func nextNonBlank(lines []string, i int) int {
	for i < len(lines) && isBlank(lines[i]) {
		i++
	}
	return i
}

// quoteRunEnd returns the index just past the run of quoted lines starting at
// lines[i], and how many lines of it carry the prefix. Blank lines inside the
// run belong to it. Blank lines after the last quoted line do not.
func quoteRunEnd(lines []string, i, limit int) (end, quoted int) {
	end = i
	for j := i; j < limit; j++ {
		switch {
		case isQuoted(lines[j]):
			quoted++
			end = j + 1
		case !isBlank(lines[j]):
			return end, quoted
		}
	}
	return end, quoted
}

// quotedRunAt reports whether the first non-blank line from i is quoted.
func quotedRunAt(lines []string, i int) bool {
	i = nextNonBlank(lines, i)
	return i < len(lines) && isQuoted(lines[i])
}

// repliesBelow reports whether a quoted run starts at the first non-blank
// line from i and is followed by more text. That text is the author's reply
// to the quote, so the run is interleaved history and not a block at the end.
func repliesBelow(lines []string, i int) bool {
	if !quotedRunAt(lines, i) {
		return false
	}
	start := nextNonBlank(lines, i)
	end, _ := quoteRunEnd(lines, start, len(lines))
	return nextNonBlank(lines, end) < len(lines)
}

func firstForward(lines []string) int {
	for i, l := range lines {
		if forwardStart.MatchString(normalize(l)) {
			return i
		}
	}
	return len(lines)
}

// StripText removes quoted history from a plain-text body.
//
// A marker from tailDetectors cuts itself and everything after it. It does
// not cut when no text of the author's own precedes it, or when the author's
// text follows the quoted lines. Runs of ">" lines collapse to a placeholder,
// and a run with nothing after it disappears. A signature after the RFC 3676
// delimiter goes. A forwarded message and everything after it is kept as
// written. A body that would end up empty comes back unchanged.
func StripText(body string) Result {
	lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	forward := firstForward(lines)

	var out []string
	var removed, placeholderBytes int
	var content, inSignature bool
	i := 0
	for i < len(lines) {
		if i >= forward {
			out = append(out, lines[i:]...)
			break
		}
		line := lines[i]
		marker := tailMarker(lines, i)
		if marker > 0 && content && !repliesBelow(lines, i+marker) {
			removed += len(lines) - i
			break
		}
		switch {
		case inSignature:
			removed++
			i++
		case isSignatureDelimiter(line):
			inSignature = true
			removed++
			i++
		case isQuoted(line) || (marker > 0 && quotedRunAt(lines, i+marker)):
			start := i
			if marker > 0 {
				start = nextNonBlank(lines, i+marker)
			}
			end, quoted := quoteRunEnd(lines, start, forward)
			removed += end - i
			i = end
			if nextNonBlank(lines[:forward], i) < forward {
				p := fmt.Sprintf("[… %d quoted %s removed]", quoted, plural(quoted))
				placeholderBytes += len(p)
				out = append(out, p+eol(line))
			}
		default:
			content = content || !isBlank(line)
			out = append(out, line)
			i++
		}
	}
	if removed == 0 {
		return unchanged(body)
	}
	text := strings.TrimRight(strings.Join(out, "\n"), " \t\r\n")
	if text == "" {
		return unchanged(body)
	}
	switch {
	case strings.HasSuffix(body, "\r\n"):
		text += "\r\n"
	case strings.HasSuffix(body, "\n"):
		text += "\n"
	}
	return Result{Text: text, RemovedBytes: len(body) - len(text) + placeholderBytes, RemovedLines: removed}
}

// eol returns the carriage return a CRLF line carries, so a placeholder
// matches the line endings around it.
func eol(line string) string {
	if strings.HasSuffix(line, "\r") {
		return "\r"
	}
	return ""
}

func plural(n int) string {
	if n == 1 {
		return "line"
	}
	return "lines"
}

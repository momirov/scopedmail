package quote

import (
	"io"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/net/html"
)

// An htmlRule recognises an element that holds quoted history. The element is
// cut with everything inside it. With toEnd, everything after it up to the end
// of the body goes too, which is how Outlook lays out a reply. A wrapper rule
// only cuts an element that holds no blockquote, so a container that holds the
// quote and the author's inline replies side by side keeps the replies.
//
// Supporting another mail client is one more row in htmlRules.
type htmlRule struct {
	name  string
	match func(toks []htmlTok, i int) bool
	toEnd bool
}

var htmlRules = []htmlRule{
	{name: "outlook-appendonsend", match: hasID("appendonsend"), toEnd: true},
	{name: "outlook-divRplyFwdMsg", match: hasID("divrplyfwdmsg", "x_divrplyfwdmsg"), toEnd: true},
	{name: "outlook-word-header", match: wordHeader, toEnd: true},
	{name: "gmail-attribution", match: hasClass("gmail_attr")},
	{name: "gmail-quote-block", match: both(isTag("blockquote"), hasClass("gmail_quote"))},
	{name: "cite-blockquote", match: both(isTag("blockquote"), hasAttr("type", "cite"))},
	{name: "thunderbird-attribution", match: hasClass("moz-cite-prefix")},
	{name: "yahoo-quoted", match: hasClass("yahoo_quoted")},
}

// htmlKeepers match elements whose whole content is kept, quoted history
// inside it included, because it is a forwarded message.
var htmlKeepers = []func(toks []htmlTok, i int) bool{
	hasClass("moz-forward-container"),
	both(both(not(isTag("blockquote")), hasClass("gmail_quote")), forwardLed),
}

type htmlTok struct {
	typ        html.TokenType
	name       string
	attrs      map[string]string
	text       string
	start, end int

	// The fields below are filled in one pass after tokenizing, so that no
	// step rescans the document from each element.

	// closer is the index of the end tag that closes this start tag, the
	// token's own index for a void or self-closing tag, and -1 when the
	// element is never closed. Only tags of the same name nest.
	closer int
	// visible is set on a text token outside script, style, title and head.
	visible bool
	// nextText is the index of the first visible text token at or after this
	// one, or len(toks).
	nextText int
	// inkBefore counts the visible text tokens before this one that hold
	// more than white space.
	inkBefore int
}

func (t htmlTok) isStart() bool {
	return t.typ == html.StartTagToken || t.typ == html.SelfClosingTagToken
}

func hasID(ids ...string) func([]htmlTok, int) bool {
	return func(toks []htmlTok, i int) bool {
		id := strings.ToLower(toks[i].attrs["id"])
		for _, want := range ids {
			if id == want {
				return true
			}
		}
		return false
	}
}

func hasClass(class string) func([]htmlTok, int) bool {
	return func(toks []htmlTok, i int) bool {
		for _, c := range strings.Fields(toks[i].attrs["class"]) {
			if c == class {
				return true
			}
		}
		return false
	}
}

func hasAttr(key, value string) func([]htmlTok, int) bool {
	return func(toks []htmlTok, i int) bool {
		return strings.EqualFold(toks[i].attrs[key], value)
	}
}

func isTag(name string) func([]htmlTok, int) bool {
	return func(toks []htmlTok, i int) bool { return toks[i].name == name }
}

func not(f func([]htmlTok, int) bool) func([]htmlTok, int) bool {
	return func(toks []htmlTok, i int) bool { return !f(toks, i) }
}

func both(a, b func([]htmlTok, int) bool) func([]htmlTok, int) bool {
	return func(toks []htmlTok, i int) bool { return a(toks, i) && b(toks, i) }
}

var (
	wordBorder = regexp.MustCompile(`(?i)border-top:\s*solid\s*#(?:e1e1e1|b5c4df)`)
	fromField  = regexp.MustCompile(`(?i)^(?:from|von|de) ?:`)
)

// wordHeader matches the rule-and-header div desktop Outlook puts above the
// message it replies to. Its first words are the from field.
func wordHeader(toks []htmlTok, i int) bool {
	return toks[i].name == "div" && wordBorder.MatchString(toks[i].attrs["style"]) &&
		fromField.MatchString(leadingText(toks, i, 40))
}

var voidElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true, "hr": true, "img": true,
	"input": true, "link": true, "meta": true, "source": true, "track": true, "wbr": true,
}

func tokenize(src string) ([]htmlTok, bool) {
	z := html.NewTokenizer(strings.NewReader(src))
	var toks []htmlTok
	pos := 0
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			return toks, z.Err() == io.EOF && pos == len(src)
		}
		t := htmlTok{typ: tt, start: pos}
		pos += len(z.Raw())
		t.end = pos
		if tt == html.TextToken {
			t.text = string(z.Text())
		}
		if tt == html.StartTagToken || tt == html.EndTagToken || tt == html.SelfClosingTagToken {
			name, more := z.TagName()
			t.name = string(name)
			if tt != html.EndTagToken {
				t.attrs = map[string]string{}
				for more {
					var k, v []byte
					k, v, more = z.TagAttr()
					t.attrs[string(k)] = string(v)
				}
			}
		}
		toks = append(toks, t)
	}
}

// index fills in closer, visible, nextText and inkBefore.
func index(toks []htmlTok) {
	open := map[string][]int{}
	skip, ink := 0, 0
	for i := range toks {
		t := &toks[i]
		t.closer, t.inkBefore = -1, ink
		switch t.typ {
		case html.SelfClosingTagToken:
			t.closer = i
		case html.StartTagToken:
			if voidElements[t.name] {
				t.closer = i
			} else {
				open[t.name] = append(open[t.name], i)
			}
			if isRawTextElement(t.name) {
				skip++
			}
		case html.EndTagToken:
			if stack := open[t.name]; len(stack) > 0 {
				toks[stack[len(stack)-1]].closer = i
				open[t.name] = stack[:len(stack)-1]
			}
			if isRawTextElement(t.name) && skip > 0 {
				skip--
			}
		case html.TextToken:
			t.visible = skip == 0
			if t.visible && strings.TrimFunc(t.text, unicode.IsSpace) != "" {
				ink++
			}
		}
	}
	next := len(toks)
	for i := len(toks) - 1; i >= 0; i-- {
		if toks[i].visible {
			next = i
		}
		toks[i].nextText = next
	}
}

// hasInk reports whether toks[from:to] hold any visible text other than white
// space, which is when visibleLines of their source would not be empty.
func hasInk(toks []htmlTok, from, to int) bool {
	after := 0
	if to < len(toks) {
		after = toks[to].inkBefore
	} else if n := len(toks); n > 0 {
		after = toks[n-1].inkBefore
		if last := toks[n-1]; last.visible && strings.TrimFunc(last.text, unicode.IsSpace) != "" {
			after++
		}
	}
	return after > toks[from].inkBefore
}

// elementEnd returns the index of the end tag that closes the element opened
// at toks[i], counting nested elements of the same name.
func elementEnd(toks []htmlTok, i int) (int, bool) {
	return toks[i].closer, toks[i].closer >= 0
}

// bodyEnd returns the index of the token where the content of the body ends,
// and its byte offset.
func bodyEnd(src string, toks []htmlTok, from int) (int, int) {
	for j := len(toks) - 1; j > from; j-- {
		if toks[j].typ == html.EndTagToken && toks[j].name == "body" {
			return j, toks[j].start
		}
	}
	return len(toks), len(src)
}

func isRawTextElement(name string) bool {
	switch name {
	case "script", "style", "title", "head":
		return true
	}
	return false
}

var blockElements = map[string]bool{
	"p": true, "div": true, "br": true, "tr": true, "li": true, "blockquote": true, "pre": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true, "table": true, "hr": true,
}

// visibleLines renders the text a reader sees, one line per block element or
// break.
func visibleLines(src string) []string {
	z := html.NewTokenizer(strings.NewReader(src))
	var b strings.Builder
	skip := 0
	for {
		switch tt := z.Next(); tt {
		case html.ErrorToken:
			var lines []string
			for _, l := range strings.Split(b.String(), "\n") {
				if l = strings.Join(strings.Fields(l), " "); l != "" {
					lines = append(lines, l)
				}
			}
			return lines
		case html.TextToken:
			if skip == 0 {
				b.Write(z.Text())
			}
		case html.StartTagToken, html.EndTagToken, html.SelfClosingTagToken:
			name, _ := z.TagName()
			switch {
			case isRawTextElement(string(name)):
				if tt == html.StartTagToken {
					skip++
				} else if tt == html.EndTagToken && skip > 0 {
					skip--
				}
			case blockElements[string(name)]:
				b.WriteByte('\n')
			}
		}
	}
}

// leadingText returns the first n bytes of visible text inside the element
// that toks[i] opens, or up to the end for an element that is never closed.
func leadingText(toks []htmlTok, i, n int) string {
	limit := len(toks)
	if end, ok := elementEnd(toks, i); ok {
		limit = end + 1
	}
	var b strings.Builder
	for j := toks[i].nextText; j < limit && b.Len() < 4*n; {
		b.WriteString(toks[j].text)
		if j++; j < len(toks) {
			j = toks[j].nextText
		}
	}
	text := strings.Join(strings.Fields(b.String()), " ")
	text = strings.NewReplacer(" ", " ", " ", " ").Replace(text)
	if len(text) > n {
		text = text[:n]
	}
	return text
}

// StripHTML removes quoted history from an HTML body. It cuts source ranges
// and leaves the rest of the markup as it came. Elements that start a
// forwarded message are kept with everything inside them. A body that would
// end up with no visible text comes back unchanged.
//
// Every step is linear in the size of the body, and a body over MaxBytes is
// not looked at.
func StripHTML(body string) Result {
	if len(body) > MaxBytes {
		return tooLarge(body)
	}
	toks, ok := tokenize(body)
	if !ok {
		return unchanged(body)
	}
	index(toks)
	var out strings.Builder
	var removedBytes, removedLines, copied int
	for i := 0; i < len(toks); {
		if !toks[i].isStart() {
			i++
			continue
		}
		rule := matchRule(toks, i)
		if keeps(toks, i) || (rule != nil && forwardLed(toks, i)) {
			end, ok := elementEnd(toks, i)
			if !ok || (rule != nil && rule.toEnd) {
				break
			}
			i = end + 1
			continue
		}
		if rule == nil {
			i++
			continue
		}
		cutEnd, next, ok := cutExtent(body, toks, i, rule)
		if !ok || !hasInk(toks, i, next) {
			i++
			continue
		}
		if rule.toEnd {
			next = len(toks)
		}
		lines := len(visibleLines(body[toks[i].start:cutEnd]))
		out.WriteString(body[copied:toks[i].start])
		removedBytes += cutEnd - toks[i].start
		removedLines += lines
		copied = cutEnd
		i = next
	}
	if removedBytes == 0 {
		return unchanged(body)
	}
	out.WriteString(body[copied:])
	text := out.String()
	if len(visibleLines(text)) == 0 {
		return unchanged(body)
	}
	return Result{Text: text, RemovedBytes: removedBytes, RemovedLines: removedLines}
}

func keeps(toks []htmlTok, i int) bool {
	for _, k := range htmlKeepers {
		if k(toks, i) {
			return true
		}
	}
	return false
}

func matchRule(toks []htmlTok, i int) *htmlRule {
	for r := range htmlRules {
		if htmlRules[r].match(toks, i) {
			return &htmlRules[r]
		}
	}
	return nil
}

// cutExtent returns the byte offset where the cut ends and the index of the
// first token after the cut. ok is false when the element has no end tag, and
// then nothing is cut.
func cutExtent(src string, toks []htmlTok, i int, r *htmlRule) (cutEnd, next int, ok bool) {
	if r.toEnd {
		next, cutEnd = bodyEnd(src, toks, i)
		return cutEnd, next, true
	}
	end, ok := elementEnd(toks, i)
	if !ok {
		return 0, 0, false
	}
	return toks[end].end, end + 1, true
}

// forwardLed reports whether the text at the start of the element is the
// header of a forwarded message.
func forwardLed(toks []htmlTok, i int) bool {
	return forwardStart.MatchString(leadingText(toks, i, 120))
}

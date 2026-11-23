package quote_test

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/momirov/scopedmail/internal/quote"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

type fixture struct {
	name string // file name without the .in.* part
	ext  string // "txt" or "html"
	in   string
}

func fixtures(t *testing.T) []fixture {
	t.Helper()
	var out []fixture
	for _, ext := range []string{"txt", "html"} {
		paths, err := filepath.Glob(filepath.Join("testdata", "*.in."+ext))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range paths {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			name := strings.TrimSuffix(filepath.Base(p), ".in."+ext)
			out = append(out, fixture{name, ext, string(b)})
		}
	}
	return out
}

func strip(f fixture, in string) quote.Result {
	if f.ext == "html" {
		return quote.StripHTML(in)
	}
	return quote.StripText(in)
}

func golden(t *testing.T, path, got string) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to create it)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs from the golden file\n--- want\n%s\n--- got\n%s", path, want, got)
	}
}

func TestCorpusGolden(t *testing.T) {
	var table strings.Builder
	var before, after, cases int
	fmt.Fprintf(&table, "%-26s %8s %8s %8s %7s\n", "case", "before", "after", "removed", "lines")
	for _, f := range fixtures(t) {
		t.Run(f.name+"."+f.ext, func(t *testing.T) {
			r := strip(f, f.in)
			golden(t, filepath.Join("testdata", f.name+".out."+f.ext), r.Text)
		})
		r := strip(f, f.in)
		fmt.Fprintf(&table, "%-26s %8d %8d %8d %7d\n", f.name+"."+f.ext, len(f.in), len(r.Text), r.RemovedBytes, r.RemovedLines)
		before += len(f.in)
		after += len(r.Text)
		cases++
	}
	fmt.Fprintf(&table, "%-26s %8d %8d   (%d cases, %.1f%% smaller)\n", "total", before, after, cases, 100*float64(before-after)/float64(before))
	golden(t, filepath.Join("testdata", "summary.golden"), table.String())
}

func TestStrippingIsIdempotent(t *testing.T) {
	for _, f := range fixtures(t) {
		once := strip(f, f.in)
		twice := strip(f, once.Text)
		if twice.Text != once.Text || twice.RemovedBytes != 0 {
			t.Errorf("%s: second pass changed the text or removed %d more bytes", f.name, twice.RemovedBytes)
		}
	}
}

func TestCRLFBodiesStripLikeLFBodies(t *testing.T) {
	crlf := func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }
	for _, f := range fixtures(t) {
		if f.ext != "txt" {
			continue
		}
		want := crlf(quote.StripText(f.in).Text)
		if got := quote.StripText(crlf(f.in)).Text; got != want {
			t.Errorf("%s: CRLF result differs\n--- want\n%q\n--- got\n%q", f.name, want, got)
		}
	}
}

func TestNothingToStripReturnsInputAndZeroCounts(t *testing.T) {
	for _, body := range []string{"", "plain note\n", "line one\nline two"} {
		if r := quote.StripText(body); r != (quote.Result{Text: body}) {
			t.Errorf("StripText(%q) = %+v", body, r)
		}
	}
	for _, body := range []string{"", "<p>plain note</p>", "<div>unclosed"} {
		if r := quote.StripHTML(body); r != (quote.Result{Text: body}) {
			t.Errorf("StripHTML(%q) = %+v", body, r)
		}
	}
}

func TestCountsDescribeWhatWasRemoved(t *testing.T) {
	body := "Thanks.\n\nOn Mon, Mar 2, 2026 at 3:04 PM Al <al@example.com> wrote:\n> one\n> two\n"
	r := quote.StripText(body)
	if r.Text != "Thanks.\n" || r.RemovedLines != 3 || r.RemovedBytes != len(body)-len(r.Text) {
		t.Errorf("result = %+v", r)
	}
}

func TestForwardSubjects(t *testing.T) {
	for subject, want := range map[string]bool{
		"Fwd: Report": true, "FW: Report": true, "WG: Bericht": true, "TR: Rapport": true, "RV: Informe": true,
		"Re: Report": false, "Re: Fwd: Report": false, "Forward planning": false, "": false,
	} {
		if got := quote.IsForwardSubject(subject); got != want {
			t.Errorf("IsForwardSubject(%q) = %v, want %v", subject, got, want)
		}
	}
}

func TestStripTextRules(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{
			"attribution with no text above is not cut",
			"On Mon, Mar 2, 2026 at 3:04 PM Al <al@example.com> wrote:\nplease call me\n",
			"On Mon, Mar 2, 2026 at 3:04 PM Al <al@example.com> wrote:\nplease call me\n",
		},
		{
			"unprefixed history after an attribution is cut",
			"Done.\n\nOn Mon, Mar 2, 2026 at 3:04 PM Al <al@example.com> wrote:\nplease call me\nthanks\n",
			"Done.\n",
		},
		{
			"french attribution with a no-break space before the colon",
			"Merci.\n\nLe 6 mars 2026 à 10:12, Camille <c@example.fr> a écrit :\nbonjour\n",
			"Merci.\n",
		},
		{
			"a sentence that ends in wrote and has no date is kept",
			"Thanks.\n\nOn Monday Ana wrote:\nship it\n",
			"Thanks.\n\nOn Monday Ana wrote:\nship it\n",
		},
		{
			"a from line with no date field is kept",
			"See below.\n\nFrom: Ana <ana@example.com>\nTo: Bo <bo@example.com>\n\nship it\n",
			"See below.\n\nFrom: Ana <ana@example.com>\nTo: Bo <bo@example.com>\n\nship it\n",
		},
		{
			"a quote followed by the author's reply keeps the reply",
			"On Mon, Mar 2, 2026 at 3:04 PM Al <al@example.com> wrote:\n> Ready?\nYes.\n",
			"[… 1 quoted line removed]\nYes.\n",
		},
		{
			"a dash line without the trailing space is not a signature",
			"Done.\n--\nAna\n",
			"Done.\n--\nAna\n",
		},
		{
			"a quote run drops with its blank lines",
			"Done.\n\n> one\n\n> two\n\n",
			"Done.\n",
		},
	}
	for _, c := range cases {
		if got := quote.StripText(c.in).Text; got != c.want {
			t.Errorf("%s\n--- want\n%q\n--- got\n%q", c.name, c.want, got)
		}
	}
}

func TestStripHTMLRules(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{
			"a blockquote without type cite is kept",
			"<p>See:</p><blockquote>fees</blockquote><p>late</p>",
			"<p>See:</p><blockquote>fees</blockquote><p>late</p>",
		},
		{
			"gmail_quote_container alone is not a quote",
			`<p>Hi</p><div class="gmail_quote_container"><p>mine</p></div>`,
			`<p>Hi</p><div class="gmail_quote_container"><p>mine</p></div>`,
		},
		{
			"an unclosed quote element is kept",
			`<p>Hi</p><blockquote type="cite"><p>quoted`,
			`<p>Hi</p><blockquote type="cite"><p>quoted`,
		},
		{
			"yahoo quote goes",
			`<p>Hi</p><div class="yahoo_quoted"><p>old</p></div><p>bye</p>`,
			`<p>Hi</p><p>bye</p>`,
		},
		{
			"nested blockquotes go as one",
			`<p>Hi</p><blockquote type="cite"><p>a</p><blockquote type="cite"><p>b</p></blockquote></blockquote><p>bye</p>`,
			`<p>Hi</p><p>bye</p>`,
		},
		{
			"style text does not count as visible text",
			`<style>p{color:red}</style><blockquote type="cite"><p>only a quote</p></blockquote>`,
			`<style>p{color:red}</style><blockquote type="cite"><p>only a quote</p></blockquote>`,
		},
	}
	for _, c := range cases {
		if got := quote.StripHTML(c.in).Text; got != c.want {
			t.Errorf("%s\n--- want\n%q\n--- got\n%q", c.name, c.want, got)
		}
	}
}

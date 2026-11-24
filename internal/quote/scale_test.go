package quote_test

import (
	"strings"
	"testing"
	"time"

	"github.com/momirov/scopedmail/internal/quote"
)

// hostileShapes are bodies an attacker can mail to make stripping rescan the
// rest of the document from every element: unclosed and nested quote
// elements with no text, and Outlook header divs with no text.
var hostileShapes = map[string]func(n int) string{
	"unclosed cite blockquotes": func(n int) string {
		return "<p>hi</p>" + strings.Repeat(`<blockquote type="cite">`, n)
	},
	"unclosed gmail_quote divs": func(n int) string {
		return "<p>hi</p>" + strings.Repeat(`<div class="gmail_quote">`, n)
	},
	"nested empty cite blockquotes": func(n int) string {
		return "<p>hi</p>" + strings.Repeat(`<blockquote type="cite">`, n/2) + strings.Repeat(`</blockquote>`, n/2)
	},
	"nested empty gmail_quote divs": func(n int) string {
		return "<p>hi</p>" + strings.Repeat(`<div class="gmail_quote">`, n/2) + strings.Repeat(`</div>`, n/2)
	},
	"empty outlook header divs": func(n int) string {
		return "<p>hi</p>" + strings.Repeat(`<div style="border-top:solid #E1E1E1 1.0pt">`, n/2) + strings.Repeat(`</div>`, n/2)
	},
}

// fastest is the best of three runs, which is the least noisy estimate of
// the work itself.
func fastest(body string) time.Duration {
	best := time.Duration(1 << 62)
	for range 3 {
		start := time.Now()
		quote.StripHTML(body)
		best = min(best, time.Since(start))
	}
	return best
}

func TestHTMLStrippingTimeGrowsLinearly(t *testing.T) {
	for name, shape := range hostileShapes {
		t.Run(name, func(t *testing.T) {
			n := (512 << 10) * 1000 / len(shape(1000)) // about 512 KiB, then 1 MiB
			t1, t2 := fastest(shape(n)), fastest(shape(2*n))
			t.Logf("%d bytes: %v, %d bytes: %v", len(shape(n)), t1, len(shape(2*n)), t2)
			// Linear work doubles. Quadratic work quadruples. The slack
			// absorbs scheduler noise on a fast run.
			if t2 > 3*t1+20*time.Millisecond {
				t.Errorf("doubling the input took %.1fx as long", float64(t2)/float64(t1))
			}
			if !raceEnabled && t2 > 500*time.Millisecond {
				t.Errorf("a %d byte body took %v, want under 500ms", len(shape(2*n)), t2)
			}
		})
	}
}

func TestOversizedBodiesAreNotStripped(t *testing.T) {
	quoted := "<p>new</p><blockquote type=\"cite\"><p>old</p></blockquote>"
	big := quoted + "<p>" + strings.Repeat("x", quote.MaxBytes) + "</p>"
	if r := quote.StripHTML(big); r.Text != big || r.RemovedBytes != 0 || !r.TooLarge {
		t.Errorf("html over the cap: removed %d bytes, too large %v", r.RemovedBytes, r.TooLarge)
	}
	text := "new\n\nOn Mon, Jan 5, 2026 at 9:00 AM Bob <bob@example.com> wrote:\n> old\n" + strings.Repeat("x", quote.MaxBytes)
	if r := quote.StripText(text); r.Text != text || r.RemovedBytes != 0 || !r.TooLarge {
		t.Errorf("text over the cap: removed %d bytes, too large %v", r.RemovedBytes, r.TooLarge)
	}
	if r := quote.StripHTML(quoted); r.TooLarge || r.RemovedBytes == 0 {
		t.Errorf("a small body was not stripped: %+v", r)
	}
}

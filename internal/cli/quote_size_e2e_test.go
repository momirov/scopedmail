package cli_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/momirov/scopedmail/internal/quote"
)

func TestReadLeavesAnOversizedBodyUnstripped(t *testing.T) {
	f := newFixture(t, readOnlyPolicy+allActions)
	filler := strings.Repeat(strings.Repeat("x", 76)+"\r\n", quote.MaxBytes/78+1)
	uid := fmt.Sprint(f.appendMessage("Agent/Sub", replyEML+filler))
	r := f.run("read", "-m", "Agent/Sub", uid)
	if r.exit != 0 {
		t.Fatalf("read: exit %d: %s", r.exit, r.stderr)
	}
	var out struct {
		Text          string
		QuotesRemoved *struct{ Bytes, Lines int } `json:"quotes_removed"`
		QuotesSkipped string                      `json:"quotes_skipped"`
	}
	r.json(t, &out)
	if out.QuotesSkipped != "too large" || out.QuotesRemoved != nil {
		t.Errorf("quotes_skipped = %q, quotes_removed = %+v; want only quotes_skipped", out.QuotesSkipped, out.QuotesRemoved)
	}
	if !strings.Contains(out.Text, "> Failures page the on-call.") {
		t.Error("the quoted history of an oversized body was cut")
	}
}

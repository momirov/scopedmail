package audit

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func appendAll(t *testing.T, recs ...Record) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, r := range recs {
		if _, err := l.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func started(action string) Record {
	return Record{Account: "work", Action: action, Mailbox: "Agent", Outcome: OutcomeStarted}
}

func finished(action string, intent uint64) Record {
	return Record{Account: "work", Action: action, Mailbox: "Agent", Outcome: OutcomeOK, IntentSeq: intent}
}

func TestVerifyListsIntentsWithNoOutcome(t *testing.T) {
	path := appendAll(t, started("delete"), started("send"), finished("send", 2), started("flag"))
	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Unfinished, []uint64{1, 4}) {
		t.Errorf("unfinished = %v, want [1 4]", res.Unfinished)
	}
}

func TestOutcomeMustCloseAnOpenIntentOfTheSameAction(t *testing.T) {
	for name, recs := range map[string][]Record{
		"no such intent":     {started("send"), finished("send", 5)},
		"closed twice":       {started("send"), finished("send", 1), finished("send", 1)},
		"other action":       {started("send"), finished("delete", 1)},
		"names a non-intent": {{Account: "work", Action: "read", Outcome: OutcomeOK}, finished("read", 1)},
	} {
		t.Run(name, func(t *testing.T) {
			wantBroken(t, appendAll(t, recs...), uint64(len(recs)))
		})
	}
}

// The testdata log was written by a build from before intents existed. Its
// records must verify unchanged, and the log must accept new records.
func TestLogFromBeforeIntentsStillVerifiesAndExtends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	src, err := os.Open("testdata/before-intents.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	dst.Close()
	res, err := Verify(path)
	if err != nil || res.Records != 4 || len(res.Unfinished) != 0 {
		t.Fatalf("verify = %+v, %v", res, err)
	}
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := l.Append(started("send")); err != nil {
		t.Fatal(err)
	}
	if res, err := Verify(path); err != nil || !slices.Equal(res.Unfinished, []uint64{5}) {
		t.Fatalf("verify after append = %+v, %v", res, err)
	}
}

func TestTailKeepsOnlyTheNamedAccount(t *testing.T) {
	other := Record{Account: "boss", Action: "read", Mailbox: "Private", Outcome: OutcomeOK}
	mine := Record{Account: "work", Action: "read", Mailbox: "Agent", Outcome: OutcomeOK}
	path := appendAll(t, mine, other, mine, other)
	recs, err := Tail(path, 10, "work")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].Seq != 1 || recs[1].Seq != 3 {
		t.Errorf("Tail = %+v, want seqs 1 and 3", recs)
	}
	if recs, _ := Tail(path, 1, "work"); len(recs) != 1 || recs[0].Seq != 3 {
		t.Errorf("Tail -n 1 = %+v, want seq 3", recs)
	}
}

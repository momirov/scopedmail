package audit

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeLog(t *testing.T, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := 1; i <= n; i++ {
		_, err := l.Append(Record{
			Account: "work",
			Action:  "read",
			Mailbox: "Agent",
			UIDs:    []uint32{uint32(i)},
			Args:    map[string]string{"n": fmt.Sprint(i)},
			Outcome: OutcomeOK,
			Count:   1,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func readLines(t *testing.T, path string) [][]byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.SplitAfter(bytes.TrimSuffix(b, []byte("\n")), []byte("\n"))
}

func writeLines(t *testing.T, path string, lines [][]byte) {
	t.Helper()
	var out []byte
	for _, l := range lines {
		out = append(out, bytes.TrimSuffix(l, []byte("\n"))...)
		out = append(out, '\n')
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

func wantBroken(t *testing.T, path string, seq uint64) {
	t.Helper()
	_, err := Verify(path)
	var be *BrokenError
	if !errors.As(err, &be) {
		t.Fatalf("Verify = %v, want BrokenError at seq %d", err, seq)
	}
	if be.Seq != seq {
		t.Fatalf("broken at seq %d (%s), want %d", be.Seq, be.Reason, seq)
	}
}

func TestVerifyCleanLog(t *testing.T) {
	path := writeLog(t, 5)
	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.Records != 5 || res.Head == "" {
		t.Errorf("result = %+v", res)
	}
}

func TestVerifyEmptyLog(t *testing.T) {
	path := writeLog(t, 0)
	res, err := Verify(path)
	if err != nil || res.Records != 0 {
		t.Errorf("Verify empty = %+v, %v", res, err)
	}
}

func TestFirstRecordHasEmptyPrevAndLaterOnesChain(t *testing.T) {
	path := writeLog(t, 3)
	recs, err := Tail(path, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if recs[0].Prev != "" {
		t.Errorf("seq 1 prev = %q, want empty", recs[0].Prev)
	}
	lines := readLines(t, path)
	if want := lineHash(bytes.TrimSuffix(lines[0], []byte("\n"))); recs[1].Prev != want {
		t.Errorf("seq 2 prev = %q, want sha256 of line 1 %q", recs[1].Prev, want)
	}
	for i, r := range recs {
		if r.Seq != uint64(i+1) {
			t.Errorf("record %d has seq %d", i, r.Seq)
		}
	}
}

func TestEditedByteIsDetectedAtItsSeq(t *testing.T) {
	for _, seq := range []int{1, 3, 5} {
		t.Run(fmt.Sprintf("seq%d", seq), func(t *testing.T) {
			path := writeLog(t, 5)
			lines := readLines(t, path)
			lines[seq-1] = bytes.Replace(lines[seq-1], []byte(`"outcome":"ok"`), []byte(`"outcome":"xx"`), 1)
			writeLines(t, path, lines)
			wantBroken(t, path, uint64(seq))
		})
	}
}

func TestEditThatRepairsHashStillBreaksTheNextRecord(t *testing.T) {
	path := writeLog(t, 4)
	lines := readLines(t, path)
	rec, err := decode(bytes.TrimSuffix(lines[1], []byte("\n")))
	if err != nil {
		t.Fatal(err)
	}
	rec.Outcome = OutcomeDenied
	rec.Hash, _ = rec.computeHash()
	forged, _ := rec.encode()
	lines[1] = forged
	writeLines(t, path, lines)
	wantBroken(t, path, 3)
}

func TestWhitespaceEditOnLastRecordIsDetected(t *testing.T) {
	path := writeLog(t, 3)
	lines := readLines(t, path)
	lines[2] = bytes.Replace(lines[2], []byte(`"seq":3,`), []byte(`"seq": 3,`), 1)
	writeLines(t, path, lines)
	wantBroken(t, path, 3)
}

func TestDeletedMiddleRecordIsDetected(t *testing.T) {
	path := writeLog(t, 5)
	lines := readLines(t, path)
	writeLines(t, path, append(lines[:2:2], lines[3:]...))
	wantBroken(t, path, 3)
}

func TestDeletedFirstRecordIsDetected(t *testing.T) {
	path := writeLog(t, 3)
	writeLines(t, path, readLines(t, path)[1:])
	wantBroken(t, path, 1)
}

func TestReorderedRecordsAreDetected(t *testing.T) {
	path := writeLog(t, 5)
	lines := readLines(t, path)
	lines[1], lines[2] = lines[2], lines[1]
	writeLines(t, path, lines)
	wantBroken(t, path, 2)
}

func TestTruncatedLastRecordIsDetected(t *testing.T) {
	path := writeLog(t, 3)
	b, _ := os.ReadFile(path)
	if err := os.WriteFile(path, b[:len(b)-20], 0o600); err != nil {
		t.Fatal(err)
	}
	wantBroken(t, path, 3)
}

func TestAppendRefusesALogThatEndsInAPartialRecord(t *testing.T) {
	path := writeLog(t, 2)
	b, _ := os.ReadFile(path)
	os.WriteFile(path, b[:len(b)-20], 0o600)
	if _, err := Open(path); err == nil {
		t.Fatal("Open succeeded on a log with a partial last record; a command must fail closed")
	}
}

func TestOpenRefusesGroupOrWorldWritableLog(t *testing.T) {
	path := writeLog(t, 1)
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("Open on mode 0660 = %v, want a writable-by-others error", err)
	}
}

func TestOpenCreatesLogWithMode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestOpenFailsWhenLogCannotBeCreated(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	os.WriteFile(blocker, nil, 0o600)
	if _, err := Open(filepath.Join(blocker, "audit.jsonl")); err == nil {
		t.Fatal("Open succeeded under a path whose parent is a file")
	}
}

func TestOpenRefusesDirectory(t *testing.T) {
	if _, err := Open(t.TempDir()); err == nil {
		t.Fatal("Open succeeded on a directory")
	}
}

func TestConcurrentAppendsFromSeparateHandlesKeepTheChainLinear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	const writers, each = 8, 25
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		l, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer l.Close()
			for i := 0; i < each; i++ {
				if _, err := l.Append(Record{Account: "a", Action: "search", Outcome: OutcomeOK}); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.Records != writers*each {
		t.Errorf("records = %d, want %d", res.Records, writers*each)
	}
}

func TestAppendStampsUTCTimeFromClock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 6, time.FixedZone("x", 3600)) }
	rec, err := l.Append(Record{Action: "read", Outcome: OutcomeOK})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Time.Location() != time.UTC || rec.Time.Hour() != 2 {
		t.Errorf("time = %v, want UTC", rec.Time)
	}
	if _, err := Verify(path); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestLongRecordsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	uids := make([]uint32, 5000)
	for i := range uids {
		uids[i] = uint32(i + 1)
	}
	for i := 0; i < 3; i++ {
		if _, err := l.Append(Record{Action: "flag", UIDs: uids, Outcome: OutcomeOK}); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	l2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen with a record longer than the tail window: %v", err)
	}
	l2.Close()
	if res, err := Verify(path); err != nil || res.Records != 3 {
		t.Errorf("Verify = %+v, %v", res, err)
	}
}

func TestTailReturnsLastNOldestFirst(t *testing.T) {
	path := writeLog(t, 6)
	recs, err := Tail(path, 2, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].Seq != 5 || recs[1].Seq != 6 {
		t.Errorf("Tail = %+v", recs)
	}
}

func TestTailRefusesTamperedLog(t *testing.T) {
	path := writeLog(t, 3)
	lines := readLines(t, path)
	lines[0] = bytes.Replace(lines[0], []byte(`"Agent"`), []byte(`"Other"`), 1)
	writeLines(t, path, lines)
	if _, err := Tail(path, 1, ""); err == nil {
		t.Fatal("Tail presented a tampered log as valid")
	}
}

func TestUnknownFieldsAreRejected(t *testing.T) {
	path := writeLog(t, 2)
	lines := readLines(t, path)
	lines[1] = bytes.Replace(lines[1], []byte(`{"seq":2,`), []byte(`{"extra":1,"seq":2,`), 1)
	writeLines(t, path, lines)
	wantBroken(t, path, 2)
}

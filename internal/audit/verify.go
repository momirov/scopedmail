package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
)

func decode(line []byte) (Record, error) {
	var r Record
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Record{}, err
	}
	return r, nil
}

// BrokenError names the first record at which the chain stops being valid.
type BrokenError struct {
	Seq    uint64
	Reason string
}

func (e *BrokenError) Error() string {
	return fmt.Sprintf("audit chain broken at seq %d: %s", e.Seq, e.Reason)
}

type VerifyResult struct {
	Records uint64 `json:"records"`
	// Head is the hash of the newest record. Pin it somewhere the agent cannot
	// write: deleting records from the end of the log leaves a valid chain, and
	// only a remembered head can reveal it.
	Head string `json:"head,omitempty"`
	// Unfinished lists intents with no outcome record, oldest first. A crash
	// or a kill leaves one, so the chain is still valid, but the action may or
	// may not have reached the server.
	Unfinished []uint64 `json:"unfinished"`
}

// Verify recomputes the chain. A BrokenError names the first bad position, so
// an edited record reports its own seq and a deleted or reordered one reports
// the position where the numbering or linkage stops matching.
func Verify(path string) (VerifyResult, error) {
	var res VerifyResult
	unfinished, err := scan(path, func(rec Record) error { res.Records, res.Head = rec.Seq, rec.Hash; return nil })
	res.Unfinished = unfinished
	return res, err
}

// Tail returns the last n records of account, oldest first, or of every
// account when account is "". It verifies the whole chain first, so a
// tampered log is never presented as trustworthy.
func Tail(path string, n int, account string) ([]Record, error) {
	var recs []Record
	_, err := scan(path, func(rec Record) error {
		if account != "" && rec.Account != account {
			return nil
		}
		recs = append(recs, rec)
		if n > 0 && len(recs) > n {
			recs = recs[1:]
		}
		return nil
	})
	return recs, err
}

// scan checks every record and its link to the one before, and returns the
// seqs of intents that no outcome closed, oldest first.
func scan(path string, visit func(Record) error) ([]uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := lock(f); err != nil {
		return nil, fmt.Errorf("audit log: lock: %w", err)
	}
	defer unlock(f)

	br := bufio.NewReader(f)
	var prevLine []byte
	open := map[uint64]Record{}
	for seq := uint64(1); ; seq++ {
		line, err := br.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			if len(line) > 0 {
				return nil, &BrokenError{seq, "partial record at end of file"}
			}
			return slices.Sorted(maps.Keys(open)), nil
		}
		if err != nil {
			return nil, err
		}
		line = line[:len(line)-1]
		rec, err := decode(line)
		if err != nil {
			return nil, &BrokenError{seq, "unreadable record: " + err.Error()}
		}
		if canon, err := rec.encode(); err != nil || !bytes.Equal(canon, line) {
			return nil, &BrokenError{seq, "record bytes differ from their canonical form"}
		}
		if rec.Seq != seq {
			return nil, &BrokenError{seq, fmt.Sprintf("found seq %d where %d belongs", rec.Seq, seq)}
		}
		wantPrev := ""
		if prevLine != nil {
			wantPrev = lineHash(prevLine)
		}
		if rec.Prev != wantPrev {
			return nil, &BrokenError{seq, "prev does not match the previous record"}
		}
		if want, err := rec.computeHash(); err != nil || rec.Hash != want {
			return nil, &BrokenError{seq, "hash does not match record contents"}
		}
		if err := link(open, rec); err != nil {
			return nil, err
		}
		if err := visit(rec); err != nil {
			return nil, err
		}
		prevLine = line
	}
}

// link pairs an outcome with the intent it names. An outcome may close only an
// earlier intent of the same account and action, and only once.
func link(open map[uint64]Record, rec Record) error {
	if rec.Outcome == OutcomeStarted {
		if rec.IntentSeq != 0 {
			return &BrokenError{rec.Seq, "an intent names another intent"}
		}
		open[rec.Seq] = rec
		return nil
	}
	if rec.IntentSeq == 0 {
		return nil
	}
	intent, ok := open[rec.IntentSeq]
	if !ok {
		return &BrokenError{rec.Seq, fmt.Sprintf("intent_seq %d names no unfinished intent", rec.IntentSeq)}
	}
	if intent.Account != rec.Account || intent.Action != rec.Action {
		return &BrokenError{rec.Seq, fmt.Sprintf("intent_seq %d is for a different account or action", rec.IntentSeq)}
	}
	delete(open, rec.IntentSeq)
	return nil
}

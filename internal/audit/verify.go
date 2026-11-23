package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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
}

// Verify recomputes the chain. A BrokenError names the first bad position, so
// an edited record reports its own seq and a deleted or reordered one reports
// the position where the numbering or linkage stops matching.
func Verify(path string) (VerifyResult, error) {
	var res VerifyResult
	err := scan(path, func(rec Record) error { res.Records, res.Head = rec.Seq, rec.Hash; return nil })
	return res, err
}

// Tail returns the last n records, oldest first, after verifying the whole
// chain so a tampered log is never presented as trustworthy.
func Tail(path string, n int) ([]Record, error) {
	var recs []Record
	err := scan(path, func(rec Record) error {
		recs = append(recs, rec)
		if n > 0 && len(recs) > n {
			recs = recs[1:]
		}
		return nil
	})
	return recs, err
}

func scan(path string, visit func(Record) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := lock(f); err != nil {
		return fmt.Errorf("audit log: lock: %w", err)
	}
	defer unlock(f)

	br := bufio.NewReader(f)
	var prevLine []byte
	for seq := uint64(1); ; seq++ {
		line, err := br.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			if len(line) > 0 {
				return &BrokenError{seq, "partial record at end of file"}
			}
			return nil
		}
		if err != nil {
			return err
		}
		line = line[:len(line)-1]
		rec, err := decode(line)
		if err != nil {
			return &BrokenError{seq, "unreadable record: " + err.Error()}
		}
		if canon, err := rec.encode(); err != nil || !bytes.Equal(canon, line) {
			return &BrokenError{seq, "record bytes differ from their canonical form"}
		}
		if rec.Seq != seq {
			return &BrokenError{seq, fmt.Sprintf("found seq %d where %d belongs", rec.Seq, seq)}
		}
		wantPrev := ""
		if prevLine != nil {
			wantPrev = lineHash(prevLine)
		}
		if rec.Prev != wantPrev {
			return &BrokenError{seq, "prev does not match the previous record"}
		}
		if want, err := rec.computeHash(); err != nil || rec.Hash != want {
			return &BrokenError{seq, "hash does not match record contents"}
		}
		if err := visit(rec); err != nil {
			return err
		}
		prevLine = line
	}
}

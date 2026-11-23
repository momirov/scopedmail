// Package audit implements the append-only, hash-chained action log.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

const (
	OutcomeOK     = "ok"
	OutcomeDenied = "denied"
	OutcomeError  = "error"
)

type Record struct {
	Seq     uint64            `json:"seq"`
	Time    time.Time         `json:"time"`
	Account string            `json:"account"`
	Action  string            `json:"action"`
	Mailbox string            `json:"mailbox,omitempty"`
	Target  string            `json:"target,omitempty"`
	UIDs    []uint32          `json:"uids,omitempty"`
	Args    map[string]string `json:"args,omitempty"`
	Outcome string            `json:"outcome"`
	Reason  string            `json:"reason,omitempty"`
	Count   int               `json:"count,omitempty"`
	Prev    string            `json:"prev"`
	Hash    string            `json:"hash"`
}

// encode is the one canonical byte form of a record. The log stores exactly
// these bytes, and verification demands each stored line equals them.
func (r Record) encode() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func (r Record) computeHash() (string, error) {
	r.Hash = ""
	b, err := r.encode()
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(r.Prev))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func lineHash(line []byte) string {
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}

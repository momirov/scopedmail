package audit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/momirov/scopedmail/internal/fsperm"
)

// Log appends records to a hash-chained JSONL file. Every Append takes an
// exclusive file lock around reading the chain head and writing the next
// record, so concurrent processes keep the chain linear.
type Log struct {
	mu   sync.Mutex
	f    *os.File
	path string
	now  func() time.Time
}

// Open creates the log when missing, refuses an unsafe or unreadable one, and
// proves the lock works and the chain head parses. Callers open the log before
// they connect anywhere, so a failure here stops the command with nothing sent.
func Open(path string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	l := &Log{f: f, path: path, now: time.Now}
	if err := l.probe(); err != nil {
		f.Close()
		return nil, fmt.Errorf("audit log %s: %w", path, err)
	}
	return l, nil
}

func (l *Log) probe() error {
	info, err := l.f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	if err := fsperm.RejectWritableByOthers(l.path, info); err != nil {
		return err
	}
	if err := raiseFileSizeLimit(info.Size()); err != nil {
		return err
	}
	if err := lock(l.f); err != nil {
		return fmt.Errorf("lock: %w", err)
	}
	defer unlock(l.f)
	_, _, err = l.head()
	return err
}

func (l *Log) Close() error { return l.f.Close() }

// Append stamps seq, time, prev and hash onto rec, writes it durably, and
// returns the stored record.
func (l *Log) Append(rec Record) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := lock(l.f); err != nil {
		return Record{}, fmt.Errorf("audit log: lock: %w", err)
	}
	defer unlock(l.f)

	last, seq, err := l.head()
	if err != nil {
		return Record{}, fmt.Errorf("audit log: %w", err)
	}
	rec.Seq = seq + 1
	rec.Time = l.now().UTC()
	rec.Prev = ""
	if last != nil {
		rec.Prev = lineHash(last)
	}
	if rec.Hash, err = rec.computeHash(); err != nil {
		return Record{}, fmt.Errorf("audit log: %w", err)
	}
	line, err := rec.encode()
	if err != nil {
		return Record{}, fmt.Errorf("audit log: %w", err)
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return Record{}, fmt.Errorf("audit log: write: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		return Record{}, fmt.Errorf("audit log: sync: %w", err)
	}
	return rec, nil
}

// head returns the last line (without its newline) and its seq, or nil and 0
// for an empty log. It refuses a log whose tail is not a well-formed record,
// because appending to one would extend a broken chain.
func (l *Log) head() ([]byte, uint64, error) {
	size, err := l.f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, 0, err
	}
	if size == 0 {
		return nil, 0, nil
	}
	var tail []byte
	for window := int64(4096); ; window *= 2 {
		if window > size {
			window = size
		}
		tail = make([]byte, window)
		if _, err := l.f.ReadAt(tail, size-window); err != nil {
			return nil, 0, err
		}
		if tail[len(tail)-1] != '\n' {
			return nil, 0, errors.New("ends with a partial record; run `scopedmail audit verify`")
		}
		body := tail[:len(tail)-1]
		if i := bytes.LastIndexByte(body, '\n'); i >= 0 {
			tail = body[i+1:]
			break
		}
		if window == size {
			tail = body
			break
		}
	}
	rec, err := decode(tail)
	if err != nil {
		return nil, 0, fmt.Errorf("last record is unreadable: %w", err)
	}
	return tail, rec.Seq, nil
}

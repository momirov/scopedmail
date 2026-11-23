package gate

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime/quotedprintable"
	"strconv"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-message/charset"
)

type leaf struct {
	path []int
	bs   *imap.BodyStructureSinglePart
}

func (l leaf) partID() string { return partID(l.path) }

func partID(path []int) string {
	s := make([]string, len(path))
	for i, n := range path {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ".")
}

func parsePartID(s string) ([]int, error) {
	if s == "" {
		return nil, fmt.Errorf("empty part number")
	}
	var path []int
	for _, seg := range strings.Split(s, ".") {
		n, err := strconv.Atoi(seg)
		if err != nil || n < 1 || seg != strconv.Itoa(n) {
			return nil, fmt.Errorf("invalid part number %q", s)
		}
		path = append(path, n)
	}
	return path, nil
}

func leaves(bs imap.BodyStructure) []leaf {
	var out []leaf
	bs.Walk(func(path []int, part imap.BodyStructure) bool {
		if sp, ok := part.(*imap.BodyStructureSinglePart); ok {
			out = append(out, leaf{path: append([]int(nil), path...), bs: sp})
		}
		return true
	})
	return out
}

// isAttachment treats anything that is not a plain inline text part as an
// attachment, including inline images and embedded messages.
func (l leaf) isAttachment() bool {
	if d := l.bs.Disposition(); d != nil && strings.EqualFold(d.Value, "attachment") {
		return true
	}
	return !strings.EqualFold(l.bs.Type, "text")
}

func (l leaf) mediaType() string { return l.bs.MediaType() }

// decodeBody undoes the part's transfer encoding.
func decodeBody(r io.Reader, encoding string) io.Reader {
	switch strings.ToLower(encoding) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, r)
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	}
	return r
}

// decodeText returns a text part as UTF-8, falling back to the raw bytes when
// the charset is unknown.
func decodeText(data []byte, l leaf) string {
	raw, err := io.ReadAll(decodeBody(bytes.NewReader(data), l.bs.Encoding))
	if err != nil && len(raw) == 0 {
		raw = data
	}
	if cs := l.bs.Params["charset"]; cs != "" {
		if r, err := charset.Reader(cs, bytes.NewReader(raw)); err == nil {
			if conv, err := io.ReadAll(r); err == nil {
				raw = conv
			}
		}
	}
	return strings.ToValidUTF8(string(raw), "�")
}

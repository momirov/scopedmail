// Package agentfs is the only place scopedmail opens a path the agent chose.
// Every such path, for reading or writing, resolves inside one operator-chosen
// directory, and the containment check is the open itself, so there is no
// window between a check and a use.
package agentfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Denied reports a path the agent may not use: files are switched off, or the
// path resolves outside the directory. The gate records it as a policy denial.
type Denied struct {
	Path   string
	Reason string
}

func (e *Denied) Error() string { return fmt.Sprintf("file %q: %s", e.Path, e.Reason) }

// ErrNotRegular is returned for a path that names something other than a
// regular file, such as a directory or a FIFO.
var ErrNotRegular = errors.New("is not a regular file")

const offReason = "file paths are off for this account; the operator must set files_dir"

// Dir is the directory agent paths resolve inside. A Dir made from an empty
// path is off and refuses every path. A relative agent path is relative to the
// directory, never to the working directory.
type Dir struct {
	path string
	root *os.Root
}

// New returns a Dir for the absolute, cleaned path, or an off Dir when path is
// empty. It does not touch the file system: the directory is opened on first
// use, so a missing directory fails only the commands that need it.
func New(path string) *Dir { return &Dir{path: path} }

// Enabled reports whether any agent path can succeed.
func (d *Dir) Enabled() bool { return d != nil && d.path != "" }

// Path is the configured directory, or "" when files are off.
func (d *Dir) Path() string {
	if !d.Enabled() {
		return ""
	}
	return d.path
}

func (d *Dir) Close() error {
	if d == nil || d.root == nil {
		return nil
	}
	r := d.root
	d.root = nil
	return r.Close()
}

// resolve turns an agent path into a name relative to the root, opening the
// root when needed. An absolute path must lie lexically under the directory,
// under its name as configured or as symlinks resolve it. The name still goes
// through os.Root, which is what stops symlink and ".." escapes.
func (d *Dir) resolve(path string) (*os.Root, string, error) {
	name, err := d.name(path)
	if err != nil {
		return nil, "", err
	}
	if d.root == nil {
		r, err := os.OpenRoot(d.path)
		if err != nil {
			return nil, "", fmt.Errorf("files_dir: %w", err)
		}
		d.root = r
	}
	return d.root, name, nil
}

// Check refuses what can be refused by looking at the name alone: files are
// off, or an absolute path lies outside the directory. It opens nothing, so the
// gate can deny before it connects. Symlink escapes surface only at the open.
func (d *Dir) Check(path string) error {
	_, err := d.name(path)
	return err
}

func (d *Dir) name(path string) (string, error) {
	if !d.Enabled() {
		return "", &Denied{Path: path, Reason: offReason}
	}
	if path == "" || strings.ContainsRune(path, 0) {
		return "", &Denied{Path: path, Reason: "not a usable path"}
	}
	if !filepath.IsAbs(path) {
		return path, nil
	}
	rel, ok := Rel(d.path, filepath.Clean(path))
	if !ok {
		return "", &Denied{Path: path, Reason: "outside files_dir"}
	}
	return rel, nil
}

// Rel returns p as a path relative to dir when p lies inside dir. It compares
// the names as given and again with symlinks resolved, so an alias such as
// /tmp for /private/tmp does not matter. It only picks a name: containment is
// enforced by os.Root when the name is opened.
func Rel(dir, p string) (string, bool) {
	for _, pair := range [][2]string{{dir, p}, {resolveLoose(dir), resolveLoose(p)}} {
		rel, err := filepath.Rel(pair[0], pair[1])
		if err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return rel, true
		}
	}
	return "", false
}

// resolveLoose follows symlinks in the longest prefix of p that exists.
func resolveLoose(p string) string {
	p = filepath.Clean(p)
	for rest := ""; ; {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Join(r, rest)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return filepath.Join(p, rest)
		}
		rest, p = filepath.Join(filepath.Base(p), rest), parent
	}
}

// escaped maps os.Root's refusal to leave the root onto Denied. os.Root
// exports no sentinel for it, so the text is the only handle; an error this
// misses still fails the operation, and the tests pin the mapping.
func escaped(path string, err error) error {
	if err != nil && strings.Contains(err.Error(), "path escapes from parent") {
		return &Denied{Path: path, Reason: "resolves outside files_dir"}
	}
	return err
}

// Open opens a regular file for reading. The caller closes it. Every check is
// on the opened handle, so nothing can change between a check and the read.
// O_NONBLOCK keeps the open of a FIFO from waiting for a writer, and it has no
// effect on reads from a regular file.
//
// os.Root stops symlinks and ".." from leaving the directory, but a hard link
// is the file itself, so it is refused unless the file has exactly one link.
// Otherwise an agent that can create links in files_dir could link a file the
// service user can read, from anywhere on the same file system, and mail it.
func (d *Dir) Open(path string) (*os.File, os.FileInfo, error) {
	r, name, err := d.resolve(path)
	if err != nil {
		return nil, nil, err
	}
	f, err := r.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, escaped(path, err)
	}
	info, err := f.Stat()
	switch {
	case err != nil:
	case !info.Mode().IsRegular():
		err = fmt.Errorf("%s %w", path, ErrNotRegular)
	case linkCount(info) != 1:
		err = &Denied{Path: path, Reason: fmt.Sprintf("has %d hard links; only a file with one link may be used", linkCount(info))}
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, info, nil
}

// Create makes a new file with mode 0600 and never replaces one: an existing
// file, or a symlink in its place, is an error. It returns the full path of
// the file it made.
func (d *Dir) Create(path string) (*os.File, string, error) {
	r, name, err := d.resolve(path)
	if err != nil {
		return nil, "", err
	}
	f, err := r.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, "", escaped(path, err)
	}
	return f, filepath.Join(d.path, name), nil
}

// Remove deletes a file Create made, for cleanup after a failed write.
func (d *Dir) Remove(path string) error {
	r, name, err := d.resolve(path)
	if err != nil {
		return err
	}
	return escaped(path, r.Remove(name))
}

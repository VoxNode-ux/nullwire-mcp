// Package cliio is the one place where nullwire-mcp opens a file whose path an
// administrator or user chose: a command-line flag or argument, or a path in a
// config file the user wrote.
//
// Those paths are trusted input by design (the tool runs as the user who types
// the command, and a relative or "../shared/key.pem" path must keep working),
// so nothing is sanitised. Each call resolves symlinks first, so a symlinked
// config, a Homebrew/Nix link or /etc/ssl/certs still works, then opens the
// resolved file's own directory as an os.Root and reads or writes the final
// name through it. The root keeps the last step from following a symlink that
// someone swaps in after the path was resolved.
//
// Do not use this package for a path that comes from the network, from a
// scanned file's content or from any other party: those need their own checks.
package cliio

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// resolveExisting returns the directory and file name of an existing path
// after following every symlink in it.
func resolveExisting(path string) (dir, base string, err error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", "", err
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return "", "", err
	}
	return filepath.Dir(abs), filepath.Base(abs), nil
}

// resolveForWrite is resolveExisting for a path that may not exist yet: when
// the file is missing, its directory is resolved instead and the name is kept.
func resolveForWrite(path string) (dir, base string, err error) {
	dir, base, err = resolveExisting(path)
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		return dir, base, err
	}
	abs, aerr := filepath.Abs(path)
	if aerr != nil {
		return "", "", aerr
	}
	d, derr := filepath.EvalSymlinks(filepath.Dir(abs))
	if derr != nil {
		return "", "", derr
	}
	return d, filepath.Base(abs), nil
}

// ReadFile is os.ReadFile for a user-chosen path.
func ReadFile(path string) ([]byte, error) {
	dir, base, err := resolveExisting(path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.ReadFile(base)
}

// Open is os.Open for a user-chosen path. The returned file stays usable after
// the root is closed.
func Open(path string) (*os.File, error) {
	dir, base, err := resolveExisting(path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.Open(base)
}

// Stat is os.Stat for a user-chosen path.
func Stat(path string) (fs.FileInfo, error) {
	dir, base, err := resolveExisting(path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.Stat(base)
}

// OpenFile is os.OpenFile for a user-chosen path that may not exist yet.
func OpenFile(path string, flag int, perm os.FileMode) (*os.File, error) {
	dir, base, err := resolveForWrite(path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.OpenFile(base, flag, perm)
}

// WriteFile is os.WriteFile for a user-chosen path.
func WriteFile(path string, data []byte, perm os.FileMode) (err error) {
	dir, base, err := resolveForWrite(path)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := root.Close(); err == nil {
			err = cerr
		}
	}()
	return root.WriteFile(base, data, perm)
}

package cliio

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReadOpenStat(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(p, []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadFile(p); err != nil || string(b) != "hi" {
		t.Fatalf("ReadFile = %q, %v", b, err)
	}
	// A relative path with ".." must keep working.
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(sub)
	if b, err := ReadFile("../f.txt"); err != nil || string(b) != "hi" {
		t.Fatalf("relative ReadFile = %q, %v", b, err)
	}
	f, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 2)
	if _, err := f.Read(b); err != nil || string(b) != "hi" {
		t.Fatalf("read from opened file = %q, %v", b, err)
	}
	_ = f.Close()
	if fi, err := Stat(p); err != nil || fi.Size() != 2 {
		t.Fatalf("Stat = %v, %v", fi, err)
	}
	if _, err := ReadFile(filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) || !os.IsNotExist(err) {
		t.Fatalf("missing file error = %v", err)
	}
	if _, err := Stat(filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing Stat error = %v", err)
	}
}

func TestSymlinksStillWork(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	realDir, links := t.TempDir(), t.TempDir()
	target := filepath.Join(realDir, "key.pem")
	if err := os.WriteFile(target, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A link into another directory (a stow/Nix/Homebrew style dotfile) and a
	// link to a directory (like /etc/ssl/certs entries) both resolve.
	link := filepath.Join(links, "key.pem")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	dirLink := filepath.Join(links, "d")
	if err := os.Symlink(realDir, dirLink); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{link, filepath.Join(dirLink, "key.pem")} {
		if b, err := ReadFile(p); err != nil || string(b) != "k" {
			t.Errorf("ReadFile(%s) = %q, %v", p, b, err)
		}
		if _, err := Stat(p); err != nil {
			t.Errorf("Stat(%s): %v", p, err)
		}
	}
	// A dangling link is a missing file.
	dangling := filepath.Join(links, "gone")
	if err := os.Symlink(filepath.Join(realDir, "nope"), dangling); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(dangling); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("dangling link error = %v", err)
	}
}

func TestWrite(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "new.key")
	f, err := OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("x")
	_ = f.Close()
	if _, err := OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second O_EXCL create = %v, want exists", err)
	}
	if err := WriteFile(p, []byte("yy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "yy" {
		t.Fatalf("after WriteFile: %q", b)
	}
	if err := WriteFile(filepath.Join(dir, "nodir", "x"), []byte("z"), 0o600); err == nil {
		t.Fatal("writing into a missing directory must fail")
	}
}

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

// brokenLink makes a symlink to an absolute target that does not exist.
func brokenLink(t *testing.T) (link, target string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	dir := t.TempDir()
	target = filepath.Join(t.TempDir(), "nope")
	link = filepath.Join(dir, "gone")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	return link, target
}

func TestMissingFileIsErrNotExist(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := ReadFile(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadFile: %v", err)
	}
	if f, err := Open(missing); !errors.Is(err, fs.ErrNotExist) || f != nil {
		t.Errorf("Open: %v, %v", f, err)
	}
	if fi, err := Stat(missing); !errors.Is(err, fs.ErrNotExist) || fi != nil {
		t.Errorf("Stat: %v, %v", fi, err)
	}
}

func TestMissingParentDir(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nodir", "file")
	if _, err := ReadFile(p); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadFile: %v", err)
	}
	if f, err := Open(p); !errors.Is(err, fs.ErrNotExist) || f != nil {
		t.Errorf("Open: %v, %v", f, err)
	}
	if _, err := Stat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Stat: %v", err)
	}
	if f, err := OpenFile(p, os.O_WRONLY|os.O_CREATE, 0o600); !errors.Is(err, fs.ErrNotExist) || f != nil {
		t.Errorf("OpenFile: %v, %v", f, err)
	}
	if err := WriteFile(p, []byte("x"), 0o600); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("WriteFile: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(p)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the missing directory must not be created: %v", err)
	}
}

func TestBrokenSymlinkRead(t *testing.T) {
	link, _ := brokenLink(t)
	if _, err := ReadFile(link); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadFile: %v", err)
	}
	if f, err := Open(link); !errors.Is(err, fs.ErrNotExist) || f != nil {
		t.Errorf("Open: %v, %v", f, err)
	}
	if fi, err := Stat(link); !errors.Is(err, fs.ErrNotExist) || fi != nil {
		t.Errorf("Stat: %v, %v", fi, err)
	}
}

// Writing through a link that points nowhere must not create the target
// outside the directory the link lives in.
func TestBrokenSymlinkWriteDoesNotEscape(t *testing.T) {
	link, target := brokenLink(t)
	if err := WriteFile(link, []byte("x"), 0o600); err == nil {
		t.Error("WriteFile through a dangling absolute link must fail")
	}
	if f, err := OpenFile(link, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err == nil {
		_ = f.Close()
		t.Error("OpenFile through a dangling absolute link must fail")
	}
	if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the link target was created: %v", err)
	}
}

func TestReadFileOfDirectoryFails(t *testing.T) {
	if _, err := ReadFile(t.TempDir()); err == nil {
		t.Error("ReadFile of a directory must fail")
	}
}

// A directory that can be searched but not read resolves fine and then cannot
// be opened as a root; every entry point reports that.
func TestUnreadableDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	existing := filepath.Join(dir, "f")
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o300); err != nil { // write and search, no read
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if _, err := ReadFile(existing); err == nil {
		t.Error("ReadFile in an unreadable directory must fail")
	}
	if f, err := Open(existing); err == nil {
		_ = f.Close()
		t.Error("Open in an unreadable directory must fail")
	}
	if _, err := Stat(existing); err == nil {
		t.Error("Stat in an unreadable directory must fail")
	}
	fresh := filepath.Join(dir, "new")
	if f, err := OpenFile(fresh, os.O_WRONLY|os.O_CREATE, 0o600); err == nil {
		_ = f.Close()
		t.Error("OpenFile in an unreadable directory must fail")
	}
	if err := WriteFile(fresh, []byte("x"), 0o600); err == nil {
		t.Error("WriteFile in an unreadable directory must fail")
	}
}

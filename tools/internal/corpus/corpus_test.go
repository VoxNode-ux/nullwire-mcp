package corpus

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func mk(t *testing.T, root, rel, data string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func walkAll(t *testing.T, root string, mod int, only bool) []string {
	t.Helper()
	var got []string
	if err := Walk(root, mod, only, func(text string) { got = append(got, text) }); err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	return got
}

func TestWalkExtensionsAndSkips(t *testing.T) {
	root := t.TempDir()
	for _, ext := range []string{".go", ".md", ".txt", ".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml", ".GO"} {
		mk(t, root, "keep/f"+ext, "keep"+ext)
	}
	for _, rel := range []string{
		"keep/image.png", "keep/noext", "keep/x_test.go",
		"keep/bigram_trained.go", "keep/trigram_trained.go",
		".git/hooks.go", "node_modules/pkg/index.js", "vendor/lib/lib.go",
		"sub/vendor/lib.go",
	} {
		mk(t, root, rel, "SKIPPED")
	}
	got := walkAll(t, root, 0, false)
	if len(got) != 11 {
		t.Fatalf("visited %d files, want 11: %v", len(got), got)
	}
	for _, g := range got {
		if strings.Contains(g, "SKIPPED") {
			t.Errorf("skipped file was visited: %q", g)
		}
	}
}

func TestWalkHoldoutPartition(t *testing.T) {
	root := t.TempDir()
	const mod = 3
	var wantHold, wantTrain []string
	for i := 0; i < 30; i++ {
		name := "f" + strings.Repeat("x", i) + ".txt"
		mk(t, root, "d/"+name, name)
		if InHoldout("d/"+name, mod) {
			wantHold = append(wantHold, name)
		} else {
			wantTrain = append(wantTrain, name)
		}
	}
	if len(wantHold) == 0 || len(wantTrain) == 0 {
		t.Fatalf("degenerate split: %d holdout / %d train", len(wantHold), len(wantTrain))
	}
	sort.Strings(wantHold)
	sort.Strings(wantTrain)
	if got := walkAll(t, root, mod, true); strings.Join(got, ",") != strings.Join(wantHold, ",") {
		t.Errorf("onlyHoldout=true visited %v, want %v", got, wantHold)
	}
	if got := walkAll(t, root, mod, false); strings.Join(got, ",") != strings.Join(wantTrain, ",") {
		t.Errorf("onlyHoldout=false visited %v, want %v", got, wantTrain)
	}
	// With the split disabled nothing is holdout, so onlyHoldout visits nothing.
	if got := walkAll(t, root, 0, true); len(got) != 0 {
		t.Errorf("mod 0, onlyHoldout=true visited %d files, want 0", len(got))
	}
}

func TestWalkSingleFileRoot(t *testing.T) {
	root := t.TempDir()
	mk(t, root, "one.md", "only")
	if got := walkAll(t, filepath.Join(root, "one.md"), 0, false); len(got) != 1 || got[0] != "only" {
		t.Errorf("got %v", got)
	}
}

func TestWalkErrors(t *testing.T) {
	if err := Walk(filepath.Join(t.TempDir(), "missing"), 0, false, func(string) {}); err == nil {
		t.Error("missing root: want error")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can read any file")
	}
	root := t.TempDir()
	mk(t, root, "locked.txt", "secret")
	if err := os.Chmod(filepath.Join(root, "locked.txt"), 0); err != nil {
		t.Fatal(err)
	}
	if err := Walk(root, 0, false, func(string) {}); err == nil {
		t.Error("unreadable file: want error")
	}
}

func TestInHoldoutDisabled(t *testing.T) {
	for _, mod := range []int{0, -5} {
		if InHoldout("a/b.go", mod) {
			t.Errorf("mod %d: want false", mod)
		}
	}
	if !InHoldout("anything", 1) {
		t.Error("mod 1 puts every file in the holdout")
	}
}

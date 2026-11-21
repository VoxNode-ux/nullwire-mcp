// Package corpus builds the reproducible training and holdout corpora shared
// by tools/bigramgen and tools/trigramgen.
//
// Polarity everywhere: benign text is the positive class and secrets are the
// negative class, matching internal/app/tokenscore.go (z -= wBigram * mean).
package corpus

import (
	"crypto/sha256"
	"encoding/binary"
	"hash/fnv"
	"io/fs"
	"math"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/VoxNode-ux/nullwire-mcp/internal/cliio"
)

const (
	MinTokenLen = 4  // shorter runs are noise
	MaxTokenLen = 64 // longer runs are blobs, not identifiers
)

// Seeds. Training and holdout use different seeds so no synthetic string is
// shared between them.
const (
	SeedTrain   = 1
	SeedHoldout = 7919
)

// IsTokByte reports whether c can be part of an identifier-like token.
func IsTokByte(c byte) bool {
	return c == '_' || c == '-' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// Tokens calls fn for every identifier-like token of text with a length in
// [MinTokenLen, MaxTokenLen] and returns how many there were.
func Tokens(text string, fn func(tok string)) int {
	n, start := 0, -1
	for i := 0; i <= len(text); i++ {
		if i < len(text) && IsTokByte(text[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if l := i - start; l >= MinTokenLen && l <= MaxTokenLen {
				fn(text[start:i])
				n++
			}
			start = -1
		}
	}
	return n
}

// detRand is a deterministic generator for the synthetic corpora: block i of
// its stream is SHA-256(seed text || i), so the same seed always gives the
// same corpus on every platform and Go version. Nothing here is secret, and it
// is not meant for anything that must be unpredictable.
type detRand struct {
	seed string
	ctr  uint64
}

func newDetRand(seed int64) *detRand { return &detRand{seed: strconv.FormatInt(seed, 10)} }

// next returns the next 63 random bits.
func (r *detRand) next() uint64 {
	var blk [8]byte
	binary.BigEndian.PutUint64(blk[:], r.ctr)
	r.ctr++
	h := sha256.New()
	h.Write([]byte(r.seed))
	h.Write(blk[:])
	var sum [sha256.Size]byte
	return binary.BigEndian.Uint64(h.Sum(sum[:0])) >> 1
}

// Intn returns a value in [0, n). n must be positive. The 63-bit draw is
// masked to the platform's int width, so it is uniform on 32- and 64-bit
// alike; the modulo bias is about n/2^31 at worst (32-bit) and below 2^-55
// on 64-bit for the small n used here.
func (r *detRand) Intn(n int) int {
	if n <= 0 {
		panic("corpus: Intn needs n > 0")
	}
	v := r.next()
	return int(v&uint64(math.MaxInt)) % n
}

// Secrets returns n realistic random secrets from a fixed seed: hex, base62
// and base64url, 16-64 bytes. Strings containing the JWT prefix "eyJ" are
// skipped and base64url strings carry at most two '-' or '_' bytes, so the
// secret class does not teach "separator means secret" and snake_case and
// kebab-case identifiers are not penalised.
func Secrets(n int, seed int64) []string {
	r := newDetRand(seed)
	const (
		hex    = "0123456789abcdef"
		hexUp  = "0123456789ABCDEF"
		base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	)
	out := make([]string, 0, n)
	for i := 0; len(out) < n; i++ {
		l := 16 + r.Intn(49) // 16..64
		b := make([]byte, l)
		switch i % 4 {
		case 0:
			fill(r, b, hex)
		case 1:
			fill(r, b, hexUp)
		case 2:
			fill(r, b, base62)
		default: // base64url with a capped number of '-' / '_'
			fill(r, b, base62)
			for k := r.Intn(3); k > 0; k-- {
				b[r.Intn(l)] = "-_"[r.Intn(2)]
			}
		}
		s := string(b)
		if strings.Contains(s, "eyJ") {
			continue
		}
		out = append(out, s)
	}
	return out
}

func fill(r *detRand, b []byte, alphabet string) {
	for j := range b {
		b[j] = alphabet[r.Intn(len(alphabet))]
	}
}

var words = strings.Fields(`
account action address admin agent alert alias allow anchor answer api append apply archive argument array
assert async attach audit auth backup balance banner base batch binary bind block body bool bound branch
bridge broker buffer build bundle byte cache call callback cancel capture card catalog chain channel check
child chunk cipher claim class clean client clock close cluster code collect column command commit common
compare compile config connect console consume content context control convert cookie copy core count
create credit cursor custom daemon data date deadline debug decode default delay delete deliver depth
derive detail device digest direct dispatch domain download driver dynamic edge element email enable
encode encrypt endpoint engine entity entry env error escape event exact exec expand expire export extend
extract factory fallback fetch field file filter final find finish fixed flag flatten flush folder follow
force format forward frame frequency function gateway generate global group guard handle hash header
health helper history hook host http icon ident idle image import index info init inline input insert
inspect install instance interval invoke item iterate job join journal json key kind label language
layer layout lease length level library limit line link list listen load local lock login logger loop
mailbox manage manifest map mask match media member memory merge message meta method metric middleware
migrate mirror mode model module monitor mount multi name native network node normal notify number object
offset online open operation option order origin output owner packet page parse partial password patch
path pattern payload peer permission pipe plan platform plugin policy pool port position prefix prepare
preview primary print priority process profile program project promise protocol provider proxy publish
query queue quota random range rate reader ready realm receive record redirect reduce refresh region
register release remote render repeat replace reply report request reserve reset resolve resource
response restore result retry return reverse review role root route router rule runtime sample sandbox
scale scan schedule schema scope script search secret section select send sequence server service
session setting shadow shape share shell signal signature simple size slice socket source space spec
split stable stack stage standard start state static status step storage store stream string struct
style submit subscribe success summary supply support switch symbol sync system table target task
template tenant test thread ticket time timeout title token topic trace track transfer transform
transport tree trigger trust tunnel type unique unit update upload usage user value vendor verify
version view virtual visit volume wait walk watch widget window worker wrap write yield zone`)

var consonants = strings.Split("b c d f g h j k l m n p r s t v w z br ch cl cr dr fl gr pl pr sh sl sp st th tr", " ")
var vowels = strings.Split("a e i o u a e i o ai ea ee ou io", " ")

// pseudoWord makes an English-like word that is not in the word list, so
// benign identifiers are not limited to a few hundred repeated words.
func pseudoWord(r *detRand) string {
	var b strings.Builder
	for k := 2 + r.Intn(3); k > 0; k-- {
		b.WriteString(consonants[r.Intn(len(consonants))])
		b.WriteString(vowels[r.Intn(len(vowels))])
	}
	if r.Intn(2) == 0 {
		b.WriteString(consonants[r.Intn(len(consonants))])
	}
	return b.String()
}

func title(s string) string { return strings.ToUpper(s[:1]) + s[1:] }

// Benign returns n synthetic identifiers (camelCase, PascalCase, snake_case,
// kebab-case, SCREAMING_CASE, optional digits) from a fixed seed. Parts come
// from a ~500 word vocabulary and from generated pseudo-words; only about
// half of the identifiers use a pseudo-word.
func Benign(n int, seed int64) []string {
	r := newDetRand(seed)
	out := make([]string, 0, n)
	for len(out) < n {
		parts := make([]string, 2+r.Intn(3))
		for i := range parts {
			if r.Intn(3) == 0 {
				parts[i] = pseudoWord(r)
			} else {
				parts[i] = words[r.Intn(len(words))]
			}
		}
		var s string
		switch r.Intn(5) {
		case 0:
			s = parts[0]
			for _, p := range parts[1:] {
				s += title(p)
			}
		case 1:
			for _, p := range parts {
				s += title(p)
			}
		case 2:
			s = strings.Join(parts, "_")
		case 3:
			s = strings.Join(parts, "-")
		default:
			s = strings.ToUpper(strings.Join(parts, "_"))
		}
		if r.Intn(6) == 0 {
			d := r.Intn(10)
			s += "0123456789"[d : d+1]
		}
		if len(s) >= MinTokenLen && len(s) <= MaxTokenLen {
			out = append(out, s)
		}
	}
	return out
}

// InHoldout reports whether the file at rel (slash-separated, relative to the
// walked root) belongs to the holdout split. mod <= 0 disables the split.
func InHoldout(rel string, mod int) bool {
	if mod <= 0 {
		return false
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(filepath.ToSlash(rel)))
	return uint64(h.Sum32())%uint64(mod) == 0
}

// Walk reads the real benign text files under root (source, docs, configs)
// and calls fn with each file's text. Files whose hash lands in the holdout
// split (see InHoldout) are skipped unless onlyHoldout is set, in which case
// only those are visited. Test files and generated tables are skipped:
// they hold fake secrets or are this pipeline's own product.
func Walk(root string, holdoutMod int, onlyHoldout bool, fn func(text string)) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == "node_modules" || n == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		base := filepath.Base(path)
		if strings.HasSuffix(path, "_test.go") || base == "bigram_trained.go" || base == "trigram_trained.go" {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".go", ".md", ".txt", ".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml":
		default:
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		if InHoldout(rel, holdoutMod) != onlyHoldout {
			return nil
		}
		data, rerr := cliio.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		fn(string(data))
		return nil
	})
}

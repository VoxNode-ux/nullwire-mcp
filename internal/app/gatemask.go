package app

import "strings"

// Bits reported by scrubGate. One pass over the text answers every "is this
// rule worth running" question at once, with no lower-cased copy of the text.
const (
	gateJWT        uint32 = 1 << iota // "eyj" (a superset of "eyJ"; the regex still decides)
	gateAPIKey                        // sk- ghp_ github_pat_ aiza xox akia
	gateBearer                        // bearer basic token
	gateSecretKey                     // token secret password passwd session_id api_key apikey key= "key"
	gateXML                           // xmlSecretHints
	gateCloud                         // cloudGate
	gateCloudPass                     // pass pwd
)

type maskGroup struct {
	bit  uint32
	lits []string
}

// maskGate is an Aho-Corasick automaton like vendors.Gate, but each state
// carries a bitmask of the groups whose literals end there (or at a suffix of
// the state). Match reads the text once and returns the union of the bits.
// ASCII case is folded into the class table at build time, so Match has no
// per-byte case branch. It allocates nothing.
type maskGate struct {
	class [256]uint8
	width int
	next  []uint16 // next[state*width+class]; state ids fit in 16 bits (checked at build)
	out   []uint32 // bits of every literal that ends at this state
	all   uint32   // union of all bits, used to stop early
}

func newMaskGate(groups ...maskGroup) *maskGate {
	g := &maskGate{}
	var used [256]bool
	for _, grp := range groups {
		g.all |= grp.bit
		for _, lit := range grp.lits {
			for i := 0; i < len(lit); i++ {
				c := lit[i]
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				used[c] = true
			}
		}
	}
	n := 1 // class 0: every byte no literal uses
	for b := 0; b < 256; b++ {
		if used[b] {
			g.class[b] = uint8(n) // #nosec G115 -- literals are ASCII, so n stays far below 256
			n++
		}
	}
	for c := byte('A'); c <= 'Z'; c++ {
		g.class[c] = g.class[c+'a'-'A'] // fold case here so Match need not
	}
	g.width = n
	next := make([]int32, n) // built wide, narrowed to uint16 at the end
	g.out = []uint32{0}

	for _, grp := range groups {
		for _, lit := range grp.lits {
			lit = strings.ToLower(lit)
			if lit == "" {
				continue
			}
			s := 0
			for i := 0; i < len(lit); i++ {
				c := int(g.class[lit[i]])
				t := next[s*n+c]
				if t == 0 {
					t = int32(len(g.out)) // #nosec G115 -- the automaton has a few hundred states
					g.out = append(g.out, 0)
					next = append(next, make([]int32, n)...)
					next[s*n+c] = t
				}
				s = int(t)
			}
			g.out[s] |= grp.bit
		}
	}

	// Breadth-first failure links; completes the transition table so Match
	// never follows a failure chain.
	fail := make([]int32, len(g.out))
	queue := make([]int32, 0, len(g.out))
	for c := 1; c < n; c++ {
		if t := next[c]; t != 0 {
			queue = append(queue, t)
		}
	}
	for len(queue) > 0 {
		s := int(queue[0])
		queue = queue[1:]
		g.out[s] |= g.out[fail[s]]
		for c := 0; c < n; c++ {
			t := next[s*n+c]
			f := next[int(fail[s])*n+c]
			if t != 0 {
				fail[t] = f
				queue = append(queue, t)
			} else {
				next[s*n+c] = f
			}
		}
	}
	if len(g.out) > 1<<16-1 {
		panic("maskGate: automaton exceeds 65535 states") // static literals; a test catches this
	}
	g.next = make([]uint16, len(next))
	for i, t := range next {
		g.next[i] = uint16(t) // #nosec G115 -- len(g.out) <= 65535 checked above
	}
	return g
}

// Match returns the union of the bits of every literal found in text.
func (g *maskGate) Match(text string) uint32 {
	next, out, class, all, n := g.next, g.out, &g.class, g.all, g.width
	var m uint32
	s := 0
	for i := 0; i < len(text); i++ {
		s = int(next[s*n+int(class[text[i]])])
		if o := out[s]; o != 0 {
			if m |= o; m == all {
				return m
			}
		}
	}
	return m
}

// scrubGate replaces strings.ToLower(in) plus six containsAny scans.
var scrubGate = lazyGate(
	maskGroup{gateJWT, []string{"eyj"}},
	maskGroup{gateAPIKey, []string{"sk-", "ghp_", "github_pat_", "aiza", "xox", "akia"}},
	maskGroup{gateBearer, []string{"bearer", "basic", "token"}},
	maskGroup{gateSecretKey, []string{"token", "secret", "password", "passwd", "session_id", "api_key", "apikey", "key=", `"key"`}},
	maskGroup{gateXML, xmlSecretHints},
	maskGroup{gateCloud, cloudGate},
	maskGroup{gateCloudPass, []string{"pass", "pwd"}},
)

// Bits reported by secretKeyGate. scrubGate's gateSecretKey bit is coarse (the
// words "token", "secret" and "password" turn up in ordinary prose), so on
// clean JSON that merely says "nothing secret here" it still sent the whole
// body through the (?i) reJSONSecret / reJSONSecretArr / reQuerySecret
// regexps, which dominate the cost of a clean scrub. These are the literals
// those regexps cannot match without, so each regexp now runs only when its
// own literal is present. The literals are exact necessary conditions taken
// from the regexps' key lists: a match of reJSONSecret needs a quoted key
// ("password" with both quotes), a match of reQuerySecret needs "<key>=".
const (
	jsonKeyBit  uint32 = 1 << iota // a quoted JSON key that reJSONSecret / reJSONSecretArr know
	queryKeyBit                    // a query/form key followed by "="
)

// secretKeyGate is kept separate from scrubGate so scrubGate's bit set stays
// the one TestScrubGateMatchesLegacyChecks pins down.
var secretKeyGate = lazyGate(
	maskGroup{jsonKeyBit, []string{
		`"access_token"`, `"refresh_token"`, `"id_token"`, `"api_key"`, `"apikey"`,
		`"secret"`, `"client_secret"`, `"password"`, `"passwd"`, `"session_id"`,
		`"auth_token"`, `"key"`,
	}},
	// api_key=, apikey= and the *_token= / *_secret= forms all end in one of these.
	maskGroup{queryKeyBit, []string{"key=", "token=", "secret=", "password=", "passwd="}},
)

// hasPANChain reports whether in holds 13 or more digits in a row, where each
// pair of digits may be one ' ' or '-' apart. It is a NECESSARY condition for
// panSpans to match anything (a card number is digits with a single space or
// hyphen allowed between two digits), so when it is false scrubPANs can be
// skipped and nothing is lost; when it is true scrubPANs still decides alone.
// It allocates nothing, stops at the first chain, and is portable Go (no
// assembly), so it behaves the same on every GOOS/GOARCH. (A longest-digit-run
// test would be wrong: "4111 1111 1111 1111" has runs of four.)
func hasPANChain(in string) bool {
	if len(in) < 13 {
		return false
	}
	// Any chain of 13 digits spans at least 13 bytes, so it covers a byte at
	// every residue mod 12, and it starts and ends on a digit with only
	// single separators inside: if the byte at k is a separator, k+1 is a
	// digit of the chain. Probing k and k+1 every 12 bytes therefore cannot
	// miss one. A probe hit is expanded both ways, and the scan resumes after
	// the span, so no byte is read twice.
	lo := 0 // bytes below lo are already accounted for
	for k := 0; k+1 < len(in); {
		var s int
		switch {
		case in[k]-'0' <= 9:
			s = k
		case in[k+1]-'0' <= 9:
			s = k + 1
		default:
			k += 12
			continue
		}
		chain := 1
		for i := s; ; {
			if i-1 >= lo && in[i-1]-'0' <= 9 {
				chain++
				i--
			} else if i-2 >= lo && (in[i-1] == ' ' || in[i-1] == '-') && in[i-2]-'0' <= 9 {
				chain++
				i -= 2
			} else {
				break
			}
		}
		if chain >= 13 {
			return true
		}
		j := s + 1
		for prevDigit := true; j < len(in); j++ {
			c := in[j]
			if c-'0' <= 9 {
				if chain++; chain >= 13 {
					return true
				}
				prevDigit = true
			} else if (c == ' ' || c == '-') && prevDigit {
				prevDigit = false
			} else {
				break
			}
		}
		lo = j + 1
		k = lo
	}
	return false
}

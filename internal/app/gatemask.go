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
// the state). Match reads the text once, folds ASCII case as it goes, and
// returns the union of the bits. It allocates nothing.
type maskGate struct {
	class [256]uint8
	width int
	next  []int32  // next[state*width+class]
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
	g.width = n
	g.next = make([]int32, n)
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
				t := g.next[s*n+c]
				if t == 0 {
					t = int32(len(g.out)) // #nosec G115 -- the automaton has a few hundred states
					g.out = append(g.out, 0)
					g.next = append(g.next, make([]int32, n)...)
					g.next[s*n+c] = t
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
		if t := g.next[c]; t != 0 {
			queue = append(queue, t)
		}
	}
	for len(queue) > 0 {
		s := int(queue[0])
		queue = queue[1:]
		g.out[s] |= g.out[fail[s]]
		for c := 0; c < n; c++ {
			t := g.next[s*n+c]
			f := g.next[int(fail[s])*n+c]
			if t != 0 {
				fail[t] = f
				queue = append(queue, t)
			} else {
				g.next[s*n+c] = f
			}
		}
	}
	return g
}

// Match returns the union of the bits of every literal found in text.
func (g *maskGate) Match(text string) uint32 {
	var m uint32
	s := 0
	n := g.width
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		s = int(g.next[s*n+int(g.class[c])])
		m |= g.out[s]
		if m == g.all {
			return m
		}
	}
	return m
}

// scrubGate replaces strings.ToLower(in) plus six containsAny scans.
var scrubGate = newMaskGate(
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
var secretKeyGate = newMaskGate(
	maskGroup{jsonKeyBit, []string{
		`"access_token"`, `"refresh_token"`, `"id_token"`, `"api_key"`, `"apikey"`,
		`"secret"`, `"client_secret"`, `"password"`, `"passwd"`, `"session_id"`,
		`"auth_token"`, `"key"`,
	}},
	// api_key=, apikey= and the *_token= / *_secret= forms all end in one of these.
	maskGroup{queryKeyBit, []string{"key=", "token=", "secret=", "password=", "passwd="}},
)

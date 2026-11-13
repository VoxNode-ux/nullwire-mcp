package vendors

import "strings"

// Prefix lists for known secret formats, in three tiers. Matching is
// case-sensitive. Each prefix must start with a letter or digit, because the
// regex puts a word boundary in front of it.
//
// A prefix is only listed when the vendor documents it or open-source secret
// scanners use it. Keys with no fixed prefix (AWS secret access keys, Azure AD
// secrets, Cloudflare global keys, Twilio and Datadog keys and so on) cannot
// be matched by prefix; cloud_secrets.go and the field-name and entropy layers
// handle them.

// DefaultVendorPrefixes: whatever follows one of these for at least 16 token
// characters is redacted.
var DefaultVendorPrefixes = []string{
	// AI and ML
	"sk-proj-", "sk-svcacct-", "sk-admin-", "sk-ant-", "sk-or-", "sk-lf-",
	"AIza", "ya29.", "GOCSPX-", "pplx-", "gsk_", "xai-", "nvapi-", "csk-",
	"api_org_", "lsv2_pt_", "lsv2_sk_", "pcsk_", "tvly-", "jina_", "sk-None-",
	"tgp_v1_",

	// AWS, Alibaba, Tencent, Yandex
	"AKIA", "ASIA", "ABIA", "ACCA", "A3T", "ABSK", "LTAI", "AKID", "AQVN",

	// Cloud, infrastructure and platform
	"AKCp", "dop_v1_", "doo_v1_", "dor_v1_", "HRKU-", "hvs.", "hvb.", "hvr.",
	"pul-", "dt0c01.", "dt0s01.", "fo1_", "fm1r_", "fm1a_", "fm2_",
	"dp.pt.", "dp.st.", "dp.sa.", "dp.ct.", "dp.scim.", "tskey-", "tk-us-",
	"pscale_tkn_", "pscale_oauth_", "pscale_pw_", "vercel_blob_rw_", "vcp_", "nfp_",
	"cfut_", "cfat_", "SSWS ", "essu_",
	"AccountKey=", "SharedAccessKey=",

	// Source hosting, CI and package registries
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
	"glpat-", "glptt-", "glrt-", "gldt-", "glft-", "glimt-", "glagent-",
	"glsoat-", "glcbt-", "gloas-",
	"ATATT3", "ATCTT3", "ATBB", "bkua_", "CCIPAT_", "CLOJARS_",
	"npm_", "pypi-AgEI", "pypi-AgEN", "rubygems_", "dckr_pat_", "dckr_oat_",
	"sgp_", "sqp_", "squ_", "sqa_",

	// Chat and webhooks
	"xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xoxe-", "xoxc-", "xoxo-", "xapp-",
	"xoxe.xoxp-", "xoxe.xoxb-",
	"hooks.slack.com/services/", "hooks.slack-gov.com/services/",
	"discord.com/api/webhooks/", "discordapp.com/api/webhooks/",
	"outlook.office.com/webhook/", "webhook.office.com/webhookb2/",

	// Payments, commerce and shipping
	"sk_live_", "sk_test_", "rk_live_", "rk_test_", "whsec_", "sq0atp-", "sq0csp-",
	"shpat_", "shpca_", "shppa_", "shpss_", "pdl_live_", "pdl_sdbx_",
	"FLWSECK-", "FLWSECK_TEST-", "shippo_live_", "shippo_test_", "EZAK", "EZTK",
	"duffel_live_", "duffel_test_",
	"access-sandbox-", "access-development-", "access-production-",

	// Messaging and email
	"SG.", "xkeysib-", "os_v2_app_", "os_v2_org_",

	// Developer, product and observability tools
	"lin_api_", "lin_oauth_", "figd_", "ntn_", "PMAK-", "sntrys_", "sntryu_",
	"NRAK-", "NRII-", "NRJS-", "glc_", "glsa_", "sbp_", "sb_secret_",
	"hcaik_", "hcxik_", "xaat-", "xapt-", "phx_", "pat-na1-", "pat-eu1-", "pat-ap1-",
	"rdme_", "pnu_", "fio-u-", "tfp_", "CFPAT-", "ops_eyJ", "sk.eyJ",
	"secret-live-", "secret-test-", "sk_car_",

	// Private key material
	"AGE-SECRET-KEY-",
}

// DefaultWeakVendorPrefixes also occur in ordinary words and identifiers
// ("secret_santa", "hf_model_dir"). They need at least 20 characters after the
// prefix, and the remainder must contain a digit or capital letter or be at
// least 24 characters long.
var DefaultWeakVendorPrefixes = []string{
	"hf_", "r8_", "cohere_", "replicate_", "supabase_", "neon_",
	"twilio_sk_", "sendgrid_", "mailgun_", "dapi",
	"secret_", "api_key_", "apikey_", "private_key_", "access_token_",
	"bearer ", "token ",
	"fw_",
}

// DefaultDSNPrefixes are connection-string and webhook-URL prefixes. The rest
// of the string (credentials, host, path) is redacted, so a shorter minimum
// applies.
var DefaultDSNPrefixes = []string{
	"mongodb+srv://", "mongodb://", "postgres://", "postgresql://",
	"postgresql+psycopg2://", "postgresql+psycopg://", "postgresql+asyncpg://", "postgresql+pg8000://",
	"mysql://", "mysql+pymysql://", "mysql+aiomysql://", "mysql+mysqlconnector://", "mysql+mysqldb://",
	"mariadb://", "mssql://", "mssql+pyodbc://", "mssql+pymssql://", "sqlserver://",
	"oracle://", "oracle+cx_oracle://", "oracle+oracledb://", "jdbc:oracle:thin:",
	"cockroachdb://", "clickhouse://", "redshift://", "snowflake://", "trino://", "cassandra://",
	"neo4j://", "neo4j+s://", "neo4j+ssc://", "bolt://", "bolt+s://",
	"couchbase://", "couchbases://", "libsql://", "cloudinary://",
	"redis://", "rediss://", "valkey://", "valkeys://",
	"amqp://", "amqps://", "nats://",
	"https://hooks.zapier.com/hooks/catch/", "https://maker.ifttt.com/use/",
	"https://chat.googleapis.com/v1/spaces/", "https://api.telegram.org/bot",
}

// Gate is an Aho-Corasick automaton that answers one question: does the text
// contain any of a fixed set of literals? It reads the text once, however many
// literals there are. Literals are lower-cased when the gate is built, so run
// Match on lower-cased text for a case-insensitive check.
type Gate struct {
	class [256]uint8 // byte -> class; every byte no literal uses shares class 0
	width int        // number of classes
	next  []int32    // flat transition table: next[state*width+class]
	hit   []bool     // state is the end of a literal, or links to one
}

// NewGate builds a gate from literals. Empty literals are ignored.
func NewGate(literals ...[]string) *Gate {
	g := &Gate{}
	var lits []string
	var used [256]bool
	for _, list := range literals {
		for _, lit := range list {
			lit = strings.ToLower(lit)
			if lit == "" {
				continue
			}
			lits = append(lits, lit)
			for i := 0; i < len(lit); i++ {
				used[lit[i]] = true
			}
		}
	}
	n := 1
	for b := 0; b < 256; b++ {
		if used[b] {
			g.class[b] = uint8(n)
			n++
		}
	}
	g.width = n
	g.next = make([]int32, n)
	g.hit = []bool{false}

	// Trie.
	for _, lit := range lits {
		s := 0
		for i := 0; i < len(lit); i++ {
			c := int(g.class[lit[i]])
			t := int(g.next[s*n+c])
			if t == 0 {
				t = len(g.hit)
				g.hit = append(g.hit, false)
				g.next = append(g.next, make([]int32, n)...)
				g.next[s*n+c] = int32(t)
			}
			s = t
		}
		g.hit[s] = true
	}

	// Failure links, filled breadth-first, turn the trie into a full DFA.
	fail := make([]int, len(g.hit))
	queue := make([]int, 0, len(g.hit))
	for c := 0; c < n; c++ {
		if t := int(g.next[c]); t != 0 {
			queue = append(queue, t)
		}
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		if g.hit[fail[s]] {
			g.hit[s] = true
		}
		for c := 0; c < n; c++ {
			t := int(g.next[s*n+c])
			f := g.next[fail[s]*n+c]
			if t != 0 {
				fail[t] = int(f)
				queue = append(queue, t)
			} else {
				g.next[s*n+c] = f
			}
		}
	}
	return g
}

// Match reports whether text contains any of the gate's literals.
func (g *Gate) Match(text string) bool {
	if g == nil || len(g.hit) <= 1 {
		return false
	}
	n := g.width
	s := 0
	for i := 0; i < len(text); i++ {
		s = int(g.next[s*n+int(g.class[text[i]])])
		if g.hit[s] {
			return true
		}
	}
	return false
}
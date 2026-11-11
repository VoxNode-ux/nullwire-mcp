package vendors

// Vendor prefixes are grouped in tiers because they differ in how safe they
// are to match. All matching is case-sensitive; the cheap pre-check that
// decides whether to run the regexes at all is case-insensitive.
//
// Only formats whose prefix is documented by the vendor, or widely seen in
// leaked-key scanners, belong here. Keys with no fixed prefix (AWS secret
// access keys, Azure and Cloudflare keys, Twilio auth tokens, Datadog keys,
// Mailchimp keys and so on) cannot be listed; the other layers handle them.

// DefaultVendorPrefixes are distinctive key formats. Anything that follows one
// of them for at least 16 token characters is redacted.
var DefaultVendorPrefixes = []string{
	// AI and ML
	"sk-proj-", "sk-svcacct-", "sk-admin-", "sk-ant-", "sk-or-",
	"AIza", "ya29.", "GOCSPX-", "pplx-", "gsk_", "xai-", "nvapi-", "csk-",
	"api_org_", "lsv2_", "pcsk_", "tvly-",

	// Cloud and infrastructure
	"AKIA", "ASIA", "AKCp", "dop_v1_", "doo_v1_", "dor_v1_", "HRKU-",
	"hvs.", "hvb.", "pul-", "dt0c01.", "fo1_", "dp.pt.", "dp.st.", "dp.sa.", "dp.ct.",
	"AccountKey=", "SharedAccessKey=",

	// Source hosting, CI and package registries
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
	"glpat-", "glptt-", "glrt-", "gldt-", "glft-", "glimt-", "glagent-", "glsoat-", "glcbt-",
	"ATATT3", "ATBB", "npm_", "pypi-AgEIcHlwaS5vcmc", "pypi-AgENdGVzdC5weXBp", "rubygems_", "dckr_pat_", "sgp_", "nfp_",

	// Chat and webhooks
	"xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xoxe-", "xapp-",
	"hooks.slack.com/services/",
	"discord.com/api/webhooks/", "discordapp.com/api/webhooks/",
	"outlook.office.com/webhook/",

	// Payments, commerce and messaging
	"sk_live_", "sk_test_", "rk_live_", "rk_test_", "whsec_", "sq0atp-", "sq0csp-", "SG.",
	"shpat_", "shpca_", "shppa_", "shpss_", "xkeysib-",
	"access-sandbox-", "access-development-", "access-production-",

	// Developer, product and observability tools
	"lin_api_", "lin_oauth_", "figd_", "ntn_", "PMAK-", "sntrys_", "sntryu_",
	"NRAK-", "NRII-", "NRJS-", "glc_", "glsa_", "sbp_", "sb_secret_",

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
}

// DefaultDSNPrefixes are connection-string schemes. The rest of the string
// (credentials, host, database) is redacted, so a shorter minimum applies.
var DefaultDSNPrefixes = []string{
	"mongodb+srv://", "mongodb://", "postgres://", "postgresql://",
	"postgresql+psycopg2://", "postgresql+asyncpg://",
	"mysql://", "mysql+pymysql://", "mysql+aiomysql://", "mariadb://",
	"mssql://", "sqlserver://", "oracle://", "cockroachdb://", "clickhouse://",
	"neo4j://", "neo4j+s://", "neo4j+ssc://", "bolt://", "bolt+s://",
	"couchbase://", "couchbases://", "libsql://",
	"redis://", "rediss://", "valkey://", "valkeys://",
	"amqp://", "amqps://", "nats://",
}

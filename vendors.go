package main

// Vendor prefixes are grouped in tiers because they differ in how safe they
// are to match. All matching is case-sensitive; the cheap pre-check that
// decides whether to run the regexes at all is case-insensitive.

// DefaultVendorPrefixes are distinctive key formats. Anything that follows one
// of them for at least 16 token characters is redacted.
var DefaultVendorPrefixes = []string{
	// AI and ML
	"sk-proj-", "sk-ant-", "sk-or-", "AIza", "ya29.", "pplx-",
	// Cloud, source hosting and package registries
	"AKIA", "ASIA", "ghp_", "github_pat_", "glpat-", "xoxb-", "xoxp-", "npm_",
	// Payments and messaging
	"sk_live_", "sk_test_", "rk_live_", "rk_test_", "sq0atp-", "SG.",
	"shpat_", "shpca_", "shppa_",
}

// DefaultWeakVendorPrefixes also occur in ordinary words and identifiers
// ("secret_santa", "hf_model_dir"). They need at least 20 characters after the
// prefix, and the remainder must contain a digit or capital letter or be at
// least 24 characters long.
var DefaultWeakVendorPrefixes = []string{
	"hf_", "r8_", "cohere_", "replicate_", "supabase_", "neon_",
	"twilio_sk_", "sendgrid_", "mailgun_",
	"secret_", "api_key_", "apikey_", "private_key_", "access_token_",
	"bearer ", "token ",
}

// DefaultDSNPrefixes are connection-string schemes. The rest of the string
// (credentials, host, database) is redacted, so a shorter minimum applies.
var DefaultDSNPrefixes = []string{
	"mongodb+srv://", "mongodb://", "postgres://", "postgresql://",
	"mysql://", "redis://", "rediss://", "amqp://", "amqps://",
}

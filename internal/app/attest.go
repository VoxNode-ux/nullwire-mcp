package app

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Local attestation reports.
//
// export_attestation (and -attest-out at exit) emit a small signed receipt:
// counts, the SHA-256 of the policy file, the active presets and a summary of
// the controls. It never holds a URL, a body, a header or a redaction tag.
//
// Signing is ECDSA P-256 over SHA-256 of the compact report bytes. Without
// -attest-key a fresh key is made for the run and its public half is put in
// the report envelope: a tamper-evident session receipt that needs no setup.
// With -attest-key the org or host key signs instead.

const (
	attestVersion = "nullwire-attestation/1"
	attestAlg     = "ECDSA-P256-SHA256"
)

type attestCounts struct {
	FlowsCaptured uint64 `json:"flows_captured"` // all flows since start, also those wiped from the ring
	RingEntries   int    `json:"ring_entries"`
	Tokens        uint64 `json:"tokens_redacted"`
	Cookies       uint64 `json:"cookies_redacted"`
	IPs           uint64 `json:"ips_redacted"`
}

type attestPolicy struct {
	ConfigSHA256 string   `json:"config_sha256"` // empty when no -secrets-config was given
	Signed       bool     `json:"signed"`        // the config passed -policy-pubkey verification
	Presets      []string `json:"presets"`
}

type attestControls struct {
	EgressAllowRules   int      `json:"egress_allow_rules"`
	EgressBlockRules   int      `json:"egress_block_rules"`
	AllowUninspectable bool     `json:"allow_uninspectable"`
	WSDeflate          bool     `json:"ws_deflate"`
	ProxyTokenRequired bool     `json:"proxy_token_required"`
	Listener           string   `json:"listener"`
	DisabledTools      []string `json:"disabled_tools"`
}

type attestReport struct {
	Version     string         `json:"version"`
	Tool        string         `json:"tool"`
	ToolVersion string         `json:"tool_version"`
	StartedAt   string         `json:"started_at"`
	GeneratedAt string         `json:"generated_at"`
	Counts      attestCounts   `json:"counts"`
	Policy      attestPolicy   `json:"policy"`
	Controls    attestControls `json:"controls"`
}

type attestSignature struct {
	Algorithm string `json:"algorithm"`
	KeyMode   string `json:"key_mode"`   // "ephemeral" or "provided"
	PublicKey string `json:"public_key"` // hex DER SubjectPublicKeyInfo
	Signature string `json:"signature"`  // hex ASN.1 ECDSA signature
}

type attestEnvelope struct {
	Report    json.RawMessage `json:"report"`
	Signature attestSignature `json:"signature"`
}

// attestInfo is what Main records for the report; the zero value is valid.
type attestInfo struct {
	started      time.Time
	policySHA    string
	policySigned bool
	presets      []string
	egressAllow  int
	egressBlock  int
	out          string
	key          *ecdsa.PrivateKey // -attest-key; nil means an ephemeral key

	once   sync.Once
	ephKey *ecdsa.PrivateKey
	ephErr error
}

func marshalCompact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func utcStamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// Total returns how many flows were ever captured, also those since wiped.
func (r *RingBuffer) Total() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.nextID - 1
}

func (a *App) attestSigner() (*ecdsa.PrivateKey, string, error) {
	if a.att.key != nil {
		return a.att.key, "provided", nil
	}
	a.att.once.Do(func() {
		a.att.ephKey, a.att.ephErr = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	})
	return a.att.ephKey, "ephemeral", a.att.ephErr
}

func (a *App) listenerKind() string {
	if a.listener == "" {
		return "tcp-loopback"
	}
	return a.listener
}

func (a *App) attestReport(now time.Time) attestReport {
	presets := append([]string{}, a.att.presets...)
	disabled := make([]string, 0, len(a.disabledTools))
	for n, off := range a.disabledTools {
		if off {
			disabled = append(disabled, n)
		}
	}
	sort.Strings(disabled)
	return attestReport{
		Version:     attestVersion,
		Tool:        serverName,
		ToolVersion: serverVersion,
		StartedAt:   utcStamp(a.att.started),
		GeneratedAt: utcStamp(now),
		Counts: attestCounts{
			FlowsCaptured: a.ring.Total(),
			RingEntries:   a.ring.Len(),
			Tokens:        a.scrub.Tokens.Load(),
			Cookies:       a.scrub.Cookies.Load(),
			IPs:           a.scrub.IPs.Load(),
		},
		Policy: attestPolicy{ConfigSHA256: a.att.policySHA, Signed: a.att.policySigned, Presets: presets},
		Controls: attestControls{
			EgressAllowRules:   a.att.egressAllow,
			EgressBlockRules:   a.att.egressBlock,
			AllowUninspectable: a.allowUninspectable,
			WSDeflate:          a.wsDeflate,
			ProxyTokenRequired: a.tokenOn,
			Listener:           a.listenerKind(),
			DisabledTools:      disabled,
		},
	}
}

// buildAttestation returns the signed envelope as one line of JSON.
func (a *App) buildAttestation() ([]byte, error) {
	body, err := marshalCompact(a.attestReport(time.Now()))
	if err != nil {
		return nil, err
	}
	key, mode, err := a.attestSigner()
	if err != nil {
		return nil, err
	}
	sig, err := signBytesHex(key, body)
	if err != nil {
		return nil, err
	}
	return marshalCompact(attestEnvelope{
		Report: body,
		Signature: attestSignature{
			Algorithm: attestAlg, KeyMode: mode,
			PublicKey: pubKeyHex(&key.PublicKey), Signature: sig,
		},
	})
}

// verifyAttestation checks an envelope against the public key it carries and
// returns the report bytes, that key (hex) and its mode. A caller that trusts
// one specific key compares the returned key with it; for an ephemeral report
// the check proves only that the report was not altered after the run signed it.
func verifyAttestation(envelope []byte) (report []byte, pubHex, mode string, err error) {
	var env attestEnvelope
	if err := json.Unmarshal(bytes.TrimSpace(envelope), &env); err != nil {
		return nil, "", "", fmt.Errorf("attestation: %v", err)
	}
	if env.Signature.Algorithm != attestAlg {
		return nil, "", "", fmt.Errorf("attestation: unsupported algorithm %q", env.Signature.Algorithm)
	}
	pub, err := decodeP256PublicKey([]byte(env.Signature.PublicKey))
	if err != nil {
		return nil, "", "", err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, env.Report); err != nil {
		return nil, "", "", fmt.Errorf("attestation report: %v", err)
	}
	if err := verifyBytesHex(pub, compact.Bytes(), env.Signature.Signature); err != nil {
		return nil, "", "", errors.New("attestation: the report does not match its signature")
	}
	// Report the key in canonical form, whatever spelling the envelope used.
	return compact.Bytes(), pubKeyHex(pub), env.Signature.KeyMode, nil
}

func (a *App) toolAttestation() map[string]any {
	env, err := a.buildAttestation()
	if err != nil {
		return toolResult("cannot build the attestation: "+err.Error(), true)
	}
	return toolResult(string(env), false)
}

// writeAttestFile writes the report to -attest-out (0600, replaced atomically).
func (a *App) writeAttestFile() error {
	if a.att.out == "" {
		return nil
	}
	env, err := a.buildAttestation()
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(a.att.out), ".nullwire-attest-*") // 0600
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(append(env, '\n')); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, a.att.out); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

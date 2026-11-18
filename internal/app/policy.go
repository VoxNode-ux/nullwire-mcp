package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// Signed offline policy packs.
//
// An admin signs the -secrets-config file with an ECDSA P-256 key
// (SHA-256 digest, ASN.1 signature, hex in <config>.sig). With
// -policy-pubkey the proxy refuses to start unless the signature checks out.
// Without it, -secrets-config behaves exactly as before. Everything is in the
// Go standard library and uses only FIPS 140-3 approved algorithms, so no
// OpenSSL is needed to make or check a pack.

const policySigSuffix = ".sig"

// spkiP256Prefix is the DER header of a P-256 SubjectPublicKeyInfo. A raw
// 65-byte uncompressed point (04||X||Y) after it makes a complete key.
var spkiP256Prefix = []byte{
	0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
}

func pubFromDER(der []byte) (*ecdsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("public key: %v", err)
	}
	pk, ok := k.(*ecdsa.PublicKey)
	if !ok || pk.Curve != elliptic.P256() {
		return nil, errors.New("public key must be ECDSA P-256")
	}
	return pk, nil
}

// decodeP256PublicKey reads a PEM "PUBLIC KEY", or hex of the DER key, or hex
// of the raw 65-byte uncompressed point.
func decodeP256PublicKey(data []byte) (*ecdsa.PublicKey, error) {
	if block, _ := pem.Decode(data); block != nil {
		return pubFromDER(block.Bytes)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, errors.New("public key is neither PEM nor hex")
	}
	if len(raw) == 65 && raw[0] == 4 {
		raw = append(append([]byte{}, spkiP256Prefix...), raw...)
	}
	return pubFromDER(raw)
}

// parsePolicyPubKey takes the -policy-pubkey value: a file (PEM or hex) or the
// hex text itself.
func parsePolicyPubKey(spec string) (*ecdsa.PublicKey, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, errors.New("empty public key")
	}
	data := []byte(spec)
	fi, statErr := os.Stat(spec) // #nosec G703 -- the path is the -policy-pubkey value the admin passed
	if statErr == nil && fi.Mode().IsRegular() {
		b, err := os.ReadFile(spec) // #nosec G304 G703 -- the path is the -policy-pubkey file the user passed
		if err != nil {
			return nil, err
		}
		data = b
	}
	return decodeP256PublicKey(data)
}

// parseP256PrivateKey reads a PKCS#8 ("PRIVATE KEY") or SEC1 ("EC PRIVATE KEY") PEM.
func parseP256PrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	var key any
	var err error
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM type %q (want PRIVATE KEY or EC PRIVATE KEY)", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("private key: %v", err)
	}
	pk, ok := key.(*ecdsa.PrivateKey)
	if !ok || pk.Curve != elliptic.P256() {
		return nil, errors.New("private key must be ECDSA P-256")
	}
	return pk, nil
}

func loadP256PrivateKeyFile(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path) // #nosec G304 G703 -- the path is a key file the user passed
	if err != nil {
		return nil, err
	}
	return parseP256PrivateKey(b)
}

func pubKeyHex(pub *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(der)
}

func signBytesHex(key *ecdsa.PrivateKey, data []byte) (string, error) {
	sum := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sig), nil
}

func verifyBytesHex(pub *ecdsa.PublicKey, data []byte, sigHex string) error {
	sig, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil {
		return errors.New("signature is not hex")
	}
	sum := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return errors.New("signature does not match the policy file")
	}
	return nil
}

// loadPolicy reads the -secrets-config file. With pubSpec set it first checks
// <path>.sig against the very bytes that are then parsed. It also returns the
// SHA-256 of those bytes for the attestation report.
func loadPolicy(path, pubSpec string) (cfg *SecretsConfig, sha string, signed bool, err error) {
	if path == "" {
		if pubSpec != "" {
			return nil, "", false, errors.New("-policy-pubkey needs -secrets-config")
		}
		return &SecretsConfig{}, "", false, nil
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- the path is the -secrets-config file the user passed
	if err != nil {
		return nil, "", false, fmt.Errorf("-secrets-config %s: %v", path, err)
	}
	if pubSpec != "" {
		pub, err := parsePolicyPubKey(pubSpec)
		if err != nil {
			return nil, "", false, fmt.Errorf("-policy-pubkey: %v", err)
		}
		sig, err := os.ReadFile(path + policySigSuffix) // #nosec G304 -- next to the policy file
		if err != nil {
			return nil, "", false, fmt.Errorf("-policy-pubkey is set but there is no signature: %v", err)
		}
		if err := verifyBytesHex(pub, raw, string(sig)); err != nil {
			return nil, "", false, fmt.Errorf("-secrets-config %s: %v", path, err)
		}
		signed = true
	}
	cfg, err = parseSecretsConfig(path, raw)
	if err != nil {
		return nil, "", false, err
	}
	sum := sha256.Sum256(raw)
	return cfg, hex.EncodeToString(sum[:]), signed, nil
}

// policyLockError reports a command-line option that would weaken a signed
// policy. It only applies when -policy-pubkey is set. Presets can only be
// added on the command line, never removed, so they need no check here.
func policyLockError(pubkeySet, allowUninspectable bool) error {
	if pubkeySet && allowUninspectable {
		return errors.New("-allow-uninspectable is refused when -policy-pubkey is set: a signed policy cannot be weakened from the command line")
	}
	return nil
}

func writeNewFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm) // #nosec G304 G703 -- output path chosen by the admin
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// RunPolicy implements "nullwire-mcp policy keygen | sign | verify | attest".
func RunPolicy(args []string, stdout, stderr io.Writer) int {
	usage := func() int {
		fmt.Fprintln(stderr, "usage: nullwire-mcp policy keygen [-out PREFIX]\n"+
			"       nullwire-mcp policy sign -key KEY.key FILE            (writes FILE.sig)\n"+
			"       nullwire-mcp policy verify -pubkey FILE|HEX FILE\n"+
			"       nullwire-mcp policy attest [-pubkey FILE|HEX] REPORT   (checks an attestation report)")
		return 2
	}
	if len(args) == 0 {
		return usage()
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "nullwire-mcp policy %s: %v\n", args[0], err)
		return 1
	}
	fs := flag.NewFlagSet("policy "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	switch args[0] {
	case "keygen":
		out := fs.String("out", "nullwire-policy", "file name prefix: writes PREFIX.key (private, 0600) and PREFIX.pub")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 0 {
			return usage()
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fail(err)
		}
		priv, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return fail(err)
		}
		pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return fail(err)
		}
		if err := writeNewFile(*out+".key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}), 0o600); err != nil {
			return fail(err)
		}
		if err := writeNewFile(*out+".pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), 0o644); err != nil { // #nosec G302 -- a public key
			return fail(err)
		}
		fmt.Fprintf(stdout, "wrote %s.key (private: keep it offline) and %s.pub\npublic key (hex, for -policy-pubkey): %s\n", *out, *out, hex.EncodeToString(pub))
		return 0
	case "sign":
		keyPath := fs.String("key", "", "private key written by policy keygen (PEM)")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 1 || *keyPath == "" {
			return usage()
		}
		key, err := loadP256PrivateKeyFile(*keyPath)
		if err != nil {
			return fail(err)
		}
		data, err := os.ReadFile(fs.Arg(0)) // #nosec G304 G703 -- the file the admin asked to sign
		if err != nil {
			return fail(err)
		}
		sig, err := signBytesHex(key, data)
		if err != nil {
			return fail(err)
		}
		if err := os.WriteFile(fs.Arg(0)+policySigSuffix, []byte(sig+"\n"), 0o644); err != nil { // #nosec G306 G703 -- a signature is public; the path is the file the admin signed plus .sig
			return fail(err)
		}
		fmt.Fprintf(stdout, "wrote %s%s\n", fs.Arg(0), policySigSuffix)
		return 0
	case "verify":
		pubSpec := fs.String("pubkey", "", "public key: PEM file, hex file or hex text")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 1 || *pubSpec == "" {
			return usage()
		}
		pub, err := parsePolicyPubKey(*pubSpec)
		if err != nil {
			return fail(err)
		}
		data, err := os.ReadFile(fs.Arg(0)) // #nosec G304 G703 -- the file the admin asked to check
		if err != nil {
			return fail(err)
		}
		sig, err := os.ReadFile(fs.Arg(0) + policySigSuffix) // #nosec G304 G703 -- next to the policy file
		if err != nil {
			return fail(err)
		}
		if err := verifyBytesHex(pub, data, string(sig)); err != nil {
			return fail(err)
		}
		fmt.Fprintln(stdout, "signature OK")
		return 0
	case "attest":
		pubSpec := fs.String("pubkey", "", "expected signer: public key (PEM file, hex file or hex text); without it only integrity is checked")
		if fs.Parse(args[1:]) != nil || fs.NArg() != 1 {
			return usage()
		}
		data, err := os.ReadFile(fs.Arg(0)) // #nosec G304 G703 -- the report the admin asked to check
		if err != nil {
			return fail(err)
		}
		_, signer, mode, err := verifyAttestation(data)
		if err != nil {
			return fail(err)
		}
		if *pubSpec != "" {
			want, err := parsePolicyPubKey(*pubSpec)
			if err != nil {
				return fail(err)
			}
			if pubKeyHex(want) != signer {
				return fail(errors.New("the report is signed by a different key than -pubkey"))
			}
			fmt.Fprintf(stdout, "attestation OK, signed by the expected key (%s)\n", mode)
			return 0
		}
		fmt.Fprintf(stdout, "attestation intact (%s key %s); the signer was not checked: pass -pubkey to pin it\n", mode, signer)
		return 0
	}
	return usage()
}

package protect

import (
	"flag"
	"fmt"
	"os"
)

// Run scans the usual config locations for secrets, then starts the
// normal server in a child process with the options it was given.
func Run(args []string) int {
	pf := flag.NewFlagSet("protect", flag.ContinueOnError)
	port := pf.Int("port", 8080, "TCP port for the diagnostic proxy (always 127.0.0.1)")
	target := pf.String("target", "", "upstream base URL(s) (see main help)")
	targetMap := pf.String("target-map", "", "fixed routes name=URL,... reached as /_gw/<name>/ (see main help)")
	cacert := pf.String("cacert", "", "extra CA certificates (PEM file or directory)")
	dnsSpec := pf.String("dns", "auto", "upstream DNS (see main help)")
	secretsConfig := pf.String("secrets-config", "", "path to -secrets-config JSON")
	clientCert := pf.String("client-cert", "", "PEM client certificate for upstream mTLS (needs -client-key)")
	clientKey := pf.String("client-key", "", "PEM private key for -client-cert")
	scrubHeaders := pf.String("scrub-headers", "", "extra sensitive headers")
	deep := pf.String("deep", "", "also scan this directory for MCP config JSON, .env and .toml files")
	history := pf.Bool("history", false, "also scan shell history during the pre-scan (opt-in; history text is never shown)")
	noScan := pf.Bool("no-scan", false, "skip the pre-scan (start directly)")
	allowUninspectable := pf.Bool("allow-uninspectable", false, "forward request bodies that cannot be inspected (br, zstd)")
	maxBody := pf.String("max-body", "", "stored body size per request/response, e.g. 1m (default 32 KiB / 256 KiB, at most 2m)")
	wsDeflate := pf.Bool("ws-deflate", false, "keep WebSocket permessage-deflate and decode it for capture")
	pf.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: nullwire-mcp protect [--port N] [--target URL] [--deep DIR] [--history] [--no-scan]\n")
		pf.PrintDefaults()
	}
	if err := pf.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if pf.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "nullwire-mcp protect: unexpected argument %q\n", pf.Arg(0))
		return 2
	}

	if (*clientCert == "") != (*clientKey == "") {
		fmt.Fprintln(os.Stderr, "nullwire-mcp protect: -client-cert and -client-key must be given together")
		return 2
	}

	if !*noScan {
		scanArgs := []string{"--discover"}
		if *deep != "" {
			scanArgs = append(scanArgs, "--deep", *deep, "--toml")
		}
		if *history {
			scanArgs = append(scanArgs, "--history")
		}
		runScanQuiet(scanArgs)
	}

	serveArgs := []string{"-port", fmt.Sprint(*port), "-dns", *dnsSpec}
	if *target != "" {
		serveArgs = append(serveArgs, "-target", *target)
	}
	if *targetMap != "" {
		serveArgs = append(serveArgs, "-target-map", *targetMap)
	}
	if *cacert != "" {
		serveArgs = append(serveArgs, "-cacert", *cacert)
	}
	if *clientCert != "" {
		serveArgs = append(serveArgs, "-client-cert", *clientCert, "-client-key", *clientKey)
	}
	if *secretsConfig != "" {
		serveArgs = append(serveArgs, "-secrets-config", *secretsConfig)
	}
	if *scrubHeaders != "" {
		serveArgs = append(serveArgs, "-scrub-headers", *scrubHeaders)
	}
	if *allowUninspectable {
		serveArgs = append(serveArgs, "-allow-uninspectable")
	}
	if *maxBody != "" {
		serveArgs = append(serveArgs, "-max-body", *maxBody)
	}
	if *wsDeflate {
		serveArgs = append(serveArgs, "-ws-deflate")
	}
	return reexecServe(serveArgs)
}

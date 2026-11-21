package app

import (
	"fmt"
	"strconv"
	"strings"
)

// bodyLimits are the size limits that depend on -max-body.
//
// reqBody and respBody are how much of a body is stored in the ring buffer.
// reqCap and respCap are how much of a body is held in memory while it flows
// through the proxy, so there is always room for the stored size plus the
// scrubWindow that is scrubbed before cutting. decoded is the most text a
// gzip or deflate body is expanded to.
//
// Whatever the limits are, capture() scrubs first and cuts second, so a secret
// that straddles the stored limit is still redacted.
type bodyLimits struct {
	reqBody, respBody int
	reqCap, respCap   int
	decoded           int
}

// maxMaxBody is the largest value -max-body accepts.
const maxMaxBody = 2 * 1024 * 1024

func defaultLimits() bodyLimits {
	return bodyLimits{
		reqBody: maxReqBody, respBody: maxRespBody,
		reqCap: maxReqCapture, respCap: maxRespCapture,
		decoded: decodedLimit,
	}
}

// limitsFor returns the limits for a -max-body value. Zero means the defaults.
// The option only ever raises a limit; it never lowers one.
func limitsFor(maxBody int) bodyLimits {
	l := defaultLimits()
	if maxBody <= 0 {
		return l
	}
	l.reqBody = max(l.reqBody, maxBody)
	l.respBody = max(l.respBody, maxBody)
	l.reqCap = max(l.reqCap, 2*maxBody)
	l.respCap = max(l.respCap, 2*maxBody)
	l.decoded = max(l.decoded, 2*maxBody)
	return l
}

// limits returns the limits in force for this App. A zero App has the defaults.
func (a *App) limits() bodyLimits { return limitsFor(a.maxBody) }

// parseMaxBody reads the -max-body value: a byte count with an optional
// k, kb, kib, m, mb or mib suffix. "" and "0" mean the defaults.
func parseMaxBody(spec string) (int, error) {
	s := strings.ToLower(strings.TrimSpace(spec))
	if s == "" || s == "0" {
		return 0, nil
	}
	mult := 1
	for _, u := range []struct {
		suffix string
		mult   int
	}{{"mib", 1 << 20}, {"mb", 1 << 20}, {"kib", 1 << 10}, {"kb", 1 << 10}, {"m", 1 << 20}, {"k", 1 << 10}, {"b", 1}} {
		if strings.HasSuffix(s, u.suffix) {
			mult = u.mult
			s = strings.TrimSpace(strings.TrimSuffix(s, u.suffix))
			break
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("-max-body: %q is not a size (try 1m, 512k or 1048576)", spec)
	}
	if n > maxMaxBody/mult {
		return 0, fmt.Errorf("-max-body: %q is above the 2 MiB limit", spec)
	}
	n *= mult
	if n < maxReqBody {
		return 0, fmt.Errorf("-max-body: %q is below the 32 KiB default; the option only raises the limit", spec)
	}
	return n, nil
}

// maxMaxRAM is the largest value -max-ram accepts.
const maxMaxRAM = 400 * 1024 * 1024

// parseMaxRAM reads the -max-ram value: a byte count with an optional k, kb,
// kib, m, mb, mib, g, gb or gib suffix. "" means off (0). Zero, negative
// values and anything above 400 MiB are errors.
func parseMaxRAM(spec string) (int, error) {
	s := strings.ToLower(strings.TrimSpace(spec))
	if s == "" {
		return 0, nil
	}
	mult := 1
	for _, u := range []struct {
		suffix string
		mult   int
	}{{"gib", 1 << 30}, {"gb", 1 << 30}, {"mib", 1 << 20}, {"mb", 1 << 20}, {"kib", 1 << 10}, {"kb", 1 << 10}, {"g", 1 << 30}, {"m", 1 << 20}, {"k", 1 << 10}, {"b", 1}} {
		if strings.HasSuffix(s, u.suffix) {
			mult = u.mult
			s = strings.TrimSpace(strings.TrimSuffix(s, u.suffix))
			break
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("-max-ram: %q is not a size (try 64m, 256m or 400m)", spec)
	}
	if n <= 0 {
		return 0, fmt.Errorf("-max-ram: %q must be greater than zero (leave the option out to turn it off)", spec)
	}
	if n > maxMaxRAM/mult {
		return 0, fmt.Errorf("-max-ram: %q is above the 400 MiB limit", spec)
	}
	return n * mult, nil
}

// validateMaxRAM checks that a -max-ram budget can hold at least one full
// flow at the -max-body limits (plus room for headers), so a flow is never
// cut just because the budget is tiny. ram 0 means the option is off.
func validateMaxRAM(ram, maxBody int) error {
	if ram <= 0 {
		return nil
	}
	l := limitsFor(maxBody)
	if need := l.reqBody + l.respBody + 64*1024; ram < need {
		return fmt.Errorf("-max-ram: %d bytes cannot hold one flow at the current body limits; use at least %d bytes", ram, need)
	}
	return nil
}

package app

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

func TestGuardrail_NumericAndUnicodeSurviveFullScrub(t *testing.T) {
	s, _ := NewScrubber()
	keep := map[string]string{
		"ns timestamps":     `{"created_at_ns": 1763218800123456789, "updated_at_ns": 1763218800987654321}`,
		"non-luhn 16 digit": `{"order_id": "4532015112830367"}`, // fails Luhn on purpose
		"unicode":           `{"city": "Guwahati असम 🚀", "note": "こんにちは世界_camelCaseIdentifier"}`,
		"user agent":        `User-Agent: Chrome/120.0.6099.109`,
		"bare key array":    `{"key": ["pk", "sk"]}`,
	}
	for name, in := range keep {
		in := in
		t.Run("keep/"+name, func(t *testing.T) {
			if out, n := s.ScrubText(in); n != 0 || out != in {
				t.Fatalf("false positive:\nwant: %s\ngot:  %s", in, out)
			}
		})
	}

	leak := map[string][2]string{ // input, substring that must not survive
		"valid PAN":      {`{"card_number": "4532 0151 1283 0366"}`, "4532"},
		"ip in url path": {`GET https://api.example.com/nodes/10.1.2.3/status`, "10.1.2.3"},
		"percent secret": {`password=%mysecret1234`, "mysecret1234"},
	}
	for name, c := range leak {
		c := c
		t.Run("redact/"+name, func(t *testing.T) {
			if out, n := s.ScrubText(c[0]); n == 0 || strings.Contains(out, c[1]) {
				t.Fatalf("leaked %q: %s", c[1], out)
			}
		})
	}

	// Token scheme in a header is a credential even when short and lowercase.
	if out, n := s.ScrubTextIn(`Token mysecretkey`, ContextHeader); n == 0 || strings.Contains(out, "mysecretkey") {
		t.Fatalf("header token leaked: %s", out)
	}
}

func TestGuardrail_ConcurrentStress(t *testing.T) {
	a := newTestApp(t)
	type payload struct{ in, secret, keep string }
	payloads := []payload{
		{`Authorization: Bearer ghp_1234567890abcdef1234567890abcdef1234`, "ghp_1234567890abcdef1234567890abcdef1234", ""},
		{`{"card": "4532015112830366", "user": "getCustomerProfile"}`, "4532015112830366", "getCustomerProfile"},
		{string(bytes.Repeat([]byte("A"), 4096)) + " sk-ant-api03-9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c", "sk-ant-api03-9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c", ""},
		{"\xff\xfe\xfd_invalid_utf8_with_secret_x9K2mQpL7vR4wZ8nJ3cF6hB5", "x9K2mQpL7vR4wZ8nJ3cF6hB5", ""},
	}

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				p := payloads[(id+i)%len(payloads)]
				out, _ := a.scrub.ScrubText(p.in)
				if p.secret != "" && strings.Contains(out, p.secret) {
					t.Errorf("secret leaked under concurrency: %q", out)
					return
				}
				if p.keep != "" && !strings.Contains(out, p.keep) {
					t.Errorf("benign value over-redacted under concurrency: %q", out)
					return
				}
				if i%33 == 0 {
					a.toolClear()
				}
			}
		}(g)
	}
	wg.Wait()
}

// scrubUnwrapped runs first whenever the text holds any %XX or \" escape, so it
// must apply the same false-positive guards as the later rules.
func TestGuardrail_UnwrapKeepsStageTwoGuards(t *testing.T) {
	s, _ := NewScrubber()
	keep := map[string]string{
		"bare key":    `{"msg": "hi \"there\"", "key": "submit"}`,
		"prose token": `{"msg": "hi \"there\"", "err": "Invalid token provided"}`,
		"env ref":     `{"msg": "hi \"there\"", "api_key": "${OPENAI_API_KEY}"}`,
		"conn string": `Server=db;Password=******;Uid=app`,
	}
	for name, in := range keep {
		in := in
		t.Run(name, func(t *testing.T) {
			if out, n := s.ScrubTextIn(in, ContextBody); n != 0 || out != in {
				t.Fatalf("false positive:\nwant: %s\ngot:  %s", in, out)
			}
		})
	}
}

func TestGuardrail_UserInfoKeepsHostAndQuery(t *testing.T) {
	s, _ := NewScrubber()
	in := `https://user:p%40ss@db.internal?email=admin@corp.com`
	out, n := s.ScrubTextIn(in, ContextBody)
	if n == 0 || strings.Contains(out, "p%40ss") {
		t.Fatalf("password leaked: %s", out)
	}
	if !strings.Contains(out, "@db.internal?email=admin@corp.com") {
		t.Fatalf("host or query destroyed: %s", out)
	}
}

func TestGuardrail_PercentPrefixedSecret(t *testing.T) {
	s, _ := NewScrubber()
	for _, in := range []string{`password=%FOO%bar_real_secret`, `password=%mysecret1234`} {
		if out, n := s.ScrubTextIn(in, ContextBody); n == 0 || strings.Contains(out, "real_secret") || strings.Contains(out, "mysecret1234") {
			t.Errorf("leaked: %q -> %q", in, out)
		}
	}
	if in := `password=%DB_PASSWORD%`; true {
		if out, _ := s.ScrubTextIn(in, ContextBody); out != in {
			t.Errorf("placeholder redacted: %q", out)
		}
	}
}
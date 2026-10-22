package service

import (
	"errors"
	"strings"
	"testing"
)

func TestBuildTrustedProxiesRejectsBroadcastPrefix(t *testing.T) {
	for _, entry := range []string{"0.0.0.0/0", "::/0"} {
		_, err := BuildTrustedProxies(TrustedProxiesInput{Entries: []string{entry}})
		if !errors.Is(err, ErrTrustedProxiesTooBroad) {
			t.Fatalf("entry %q: expected ErrTrustedProxiesTooBroad, got %v", entry, err)
		}
	}
}

func TestBuildTrustedProxiesRejectsInvalidEntry(t *testing.T) {
	for _, entry := range []string{"not-an-ip", "10.0.0.0/33", "1.2.3.4:80", "  "} {
		_, err := BuildTrustedProxies(TrustedProxiesInput{Entries: []string{entry}})
		if !errors.Is(err, ErrTrustedProxiesInvalid) && !errors.Is(err, ErrTrustedProxiesEmpty) {
			t.Fatalf("entry %q: expected validation error, got %v", entry, err)
		}
	}
}

func TestBuildTrustedProxiesRequiresAtLeastOneEntry(t *testing.T) {
	_, err := BuildTrustedProxies(TrustedProxiesInput{Entries: []string{"", "   "}})
	if !errors.Is(err, ErrTrustedProxiesEmpty) {
		t.Fatalf("expected ErrTrustedProxiesEmpty, got %v", err)
	}
}

func TestBuildTrustedProxiesNoneMustStandAlone(t *testing.T) {
	if _, err := BuildTrustedProxies(TrustedProxiesInput{Entries: []string{"none", "10.0.0.0/8"}}); !errors.Is(err, ErrTrustedProxiesNoneMixed) {
		t.Fatalf("expected ErrTrustedProxiesNoneMixed for mixed entries, got %v", err)
	}
	if _, err := BuildTrustedProxies(TrustedProxiesInput{Entries: []string{"None"}, IncludeLoopback: true}); !errors.Is(err, ErrTrustedProxiesNoneMixed) {
		t.Fatalf("expected ErrTrustedProxiesNoneMixed when loopback is appended to none, got %v", err)
	}

	result, err := BuildTrustedProxies(TrustedProxiesInput{Entries: []string{" NONE "}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Value != TrustedProxiesNone {
		t.Fatalf("expected value %q, got %q", TrustedProxiesNone, result.Value)
	}
}

func TestBuildTrustedProxiesNormalizesBareIPToPrefix(t *testing.T) {
	result, err := BuildTrustedProxies(TrustedProxiesInput{Entries: []string{"203.0.113.7", " 198.51.100.0/24 "}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "198.51.100.0/24,203.0.113.7/32"
	if result.Value != want {
		t.Fatalf("expected %q, got %q", want, result.Value)
	}
}

func TestBuildTrustedProxiesMasksPrefixAndDedupes(t *testing.T) {
	result, err := BuildTrustedProxies(TrustedProxiesInput{
		Entries: []string{"203.0.113.7/24", "203.0.113.0/24", "203.0.113.99", "203.0.113.7/24"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "203.0.113.0/24,203.0.113.99/32"
	if result.Value != want {
		t.Fatalf("expected %q, got %q", want, result.Value)
	}
	if result.Dropped != 2 {
		t.Fatalf("expected 2 dropped duplicates, got %d", result.Dropped)
	}
}

func TestBuildTrustedProxiesAppendsLoopbackForLocalProxy(t *testing.T) {
	result, err := BuildTrustedProxies(TrustedProxiesInput{
		Entries:         []string{"203.0.113.0/24"},
		IncludeLoopback: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "127.0.0.1/32,203.0.113.0/24"
	if result.Value != want {
		t.Fatalf("expected %q, got %q", want, result.Value)
	}
}

func TestBuildTrustedProxiesWarnsOnPublicSingleAddress(t *testing.T) {
	result, err := BuildTrustedProxies(TrustedProxiesInput{Entries: []string{"203.0.113.7"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Warnings) == 0 || !strings.Contains(result.Warnings[0], "公网单地址") {
		t.Fatalf("expected a public single-address warning, got %#v", result.Warnings)
	}
}

func TestClassifyTrustedProxies(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want TrustedProxiesStatus
	}{
		{"unset", "", TrustedProxiesStatusMissing},
		{"blank", "   ", TrustedProxiesStatusMissing},
		{"none", "none", TrustedProxiesStatusNone},
		{"none upper", " NONE ", TrustedProxiesStatusNone},
		{"configured", "127.0.0.1,203.0.113.0/24", TrustedProxiesStatusConfigured},
		{"invalid", "127.0.0.1,not-an-ip", TrustedProxiesStatusInvalid},
		{"only separators", ", ,", TrustedProxiesStatusInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := ClassifyTrustedProxies(tc.raw)
			if got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestTrustedProxiesContainsPublicPeer(t *testing.T) {
	cases := []struct {
		name    string
		entries []string
		want    bool
	}{
		{"empty", nil, false},
		{"default newapi private only", []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "::1"}, false},
		{"public cdn range", []string{"127.0.0.1/32", "173.245.48.0/20"}, true},
		{"invalid ignored", []string{"garbage"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := TrustedProxiesContainsPublicPeer(tc.entries); got != tc.want {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
		})
	}
}

func TestTrustedProxiesDotEnvBlockIsStable(t *testing.T) {
	block := TrustedProxiesDotEnvBlock("127.0.0.1/32,203.0.113.0/24")
	if !strings.Contains(block, TrustedProxiesDotEnvBegin) || !strings.Contains(block, TrustedProxiesDotEnvEnd) {
		t.Fatalf("block missing markers: %q", block)
	}
	if !strings.Contains(block, "TRUSTED_PROXIES=127.0.0.1/32,203.0.113.0/24") {
		t.Fatalf("block missing value: %q", block)
	}
	if strings.Count(block, "TRUSTED_PROXIES=") != 1 {
		t.Fatalf("block must declare TRUSTED_PROXIES exactly once: %q", block)
	}
}

func TestTrustedProxiesOverlayYAML(t *testing.T) {
	yaml := TrustedProxiesOverlayYAML("new-api", "127.0.0.1/32,203.0.113.0/24")
	for _, want := range []string{"services:", "  new-api:", "environment:", "TRUSTED_PROXIES:", "203.0.113.0/24"} {
		if !strings.Contains(yaml, want) {
			t.Fatalf("overlay missing %q:\n%s", want, yaml)
		}
	}
	// 覆盖层应把 .env 里的值作为可被 override 的默认值，而不是硬编码。
	if !strings.Contains(yaml, "${TRUSTED_PROXIES:-") {
		t.Fatalf("overlay should defer to .env when present:\n%s", yaml)
	}
	if !strings.Contains(yaml, "}") {
		t.Fatalf("overlay default-value expression is not closed:\n%s", yaml)
	}
}

func TestSuggestedTrustedProxiesForCDN(t *testing.T) {
	if got := SuggestedTrustedProxiesForCDN("cloudflare"); len(got) == 0 {
		t.Fatal("expected cloudflare suggestions")
	}
	if got := SuggestedTrustedProxiesForCDN("unknown-vendor"); got != nil {
		t.Fatalf("expected nil for unknown vendor, got %#v", got)
	}
	for _, entry := range SuggestedTrustedProxiesForCDN("cloudflare") {
		if _, err := BuildTrustedProxies(TrustedProxiesInput{Entries: []string{entry}}); err != nil {
			t.Fatalf("suggested entry %q failed validation: %v", entry, err)
		}
	}
}

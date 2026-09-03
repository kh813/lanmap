package i18n

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetectLanguage(t *testing.T) {
	// 1. Default fallback (no headers, no cookies)
	req := httptest.NewRequest("GET", "/", nil)
	if got := DetectLanguage(req); got != LangEN {
		t.Errorf("expected %s, got %s", LangEN, got)
	}

	// 2. Accept-Language header ja
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Language", "ja,en-US;q=0.9,en;q=0.8")
	if got := DetectLanguage(req); got != LangJA {
		t.Errorf("expected %s, got %s", LangJA, got)
	}

	// 3. Accept-Language header en-US
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	if got := DetectLanguage(req); got != LangEN {
		t.Errorf("expected %s, got %s", LangEN, got)
	}

	// 4. Query param overrides header
	req = httptest.NewRequest("GET", "/?lang=en", nil)
	req.Header.Set("Accept-Language", "ja")
	if got := DetectLanguage(req); got != LangEN {
		t.Errorf("expected %s, got %s", LangEN, got)
	}

	// 5. Cookie overrides everything
	req = httptest.NewRequest("GET", "/?lang=en", nil)
	req.Header.Set("Accept-Language", "en")
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "ja"})
	if got := DetectLanguage(req); got != LangJA {
		t.Errorf("expected %s, got %s", LangJA, got)
	}
}

func TestT(t *testing.T) {
	// English translation
	if got := T("en", "col_hostname"); got != "Hostname" {
		t.Errorf("expected Hostname, got %s", got)
	}

	// Japanese translation
	if got := T("ja", "col_hostname"); got != "ホスト名" {
		t.Errorf("expected ホスト名, got %s", got)
	}

	// Formatting with args
	if got := TF("ja", "sidebar_unadded_badge", 3); got != "未登録のローカルNICが 3 件あります" {
		t.Errorf("expected formatted string, got %s", got)
	}

	// Missing key fallback
	if got := T("en", "non_existent_key"); got != "non_existent_key" {
		t.Errorf("expected non_existent_key, got %s", got)
	}
}

func TestDictionaryConsistency(t *testing.T) {
	enDict := translations[LangEN]
	jaDict := translations[LangJA]

	for k := range enDict {
		if _, ok := jaDict[k]; !ok {
			t.Errorf("key %s present in EN but missing in JA", k)
		}
	}

	for k := range jaDict {
		if _, ok := enDict[k]; !ok {
			t.Errorf("key %s present in JA but missing in EN", k)
		}
	}
}

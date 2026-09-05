package federation

import (
	"testing"
)

func TestParseVersion(t *testing.T) {
	maj, min, patch, err := ParseVersion("v0.0.16")
	if err != nil {
		t.Fatalf("ParseVersion failed: %v", err)
	}
	if maj != 0 || min != 0 || patch != 16 {
		t.Fatalf("unexpected version parsed: %d.%d.%d", maj, min, patch)
	}

	maj, min, patch, err = ParseVersion("1.2.3-rc1")
	if err != nil {
		t.Fatalf("ParseVersion failed: %v", err)
	}
	if maj != 1 || min != 2 || patch != 3 {
		t.Fatalf("unexpected version parsed: %d.%d.%d", maj, min, patch)
	}
}

func TestCheckVersionCompatibility(t *testing.T) {
	// 1. Identical
	mismatch, err := CheckVersionCompatibility("v0.0.16", "v0.0.16")
	if err != nil || mismatch {
		t.Fatalf("expected match, got mismatch=%v, err=%v", mismatch, err)
	}

	// 2. Minor/Patch Mismatch (Compatible but warned)
	mismatch, err = CheckVersionCompatibility("v0.0.16", "v0.0.17")
	if err != nil || !mismatch {
		t.Fatalf("expected mismatch=true and no error, got mismatch=%v, err=%v", mismatch, err)
	}

	// 3. Major Mismatch (Incompatible - error)
	mismatch, err = CheckVersionCompatibility("v1.0.0", "v2.0.0")
	if err == nil {
		t.Fatalf("expected major version error, got nil (mismatch=%v)", mismatch)
	}
}

package guardrails

import (
	"testing"
)

func TestReadPackYAML(t *testing.T) {
	pack, err := readPack("packs/baseline.yaml", ".yaml")
	if err != nil {
		t.Fatalf("readPack: %v", err)
	}
	if pack.Metadata.Name != "baseline-standards" {
		t.Fatalf("unexpected pack name: %q", pack.Metadata.Name)
	}
	if len(pack.Spec.Guardrails) != 3 {
		t.Fatalf("expected 3 guardrails, got %d", len(pack.Spec.Guardrails))
	}

	ids := map[string]bool{}
	for _, g := range pack.Spec.Guardrails {
		ids[g.ID] = true
	}
	for _, want := range []string{"GR-IMG-001", "GR-NS-001", "GR-ND-001"} {
		if !ids[want] {
			t.Errorf("missing guardrail %s", want)
		}
	}
}

func TestReadPackPodSecurityYAML(t *testing.T) {
	pack, err := readPack("packs/pod-security.yaml", ".yaml")
	if err != nil {
		t.Fatalf("readPack: %v", err)
	}
	if pack.Metadata.Name != "pod-security-standards" {
		t.Fatalf("unexpected pack name: %q", pack.Metadata.Name)
	}
	if len(pack.Spec.Guardrails) != 3 {
		t.Fatalf("expected 3 guardrails, got %d", len(pack.Spec.Guardrails))
	}
}

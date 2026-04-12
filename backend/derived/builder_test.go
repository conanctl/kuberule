package derived

import (
	"encoding/json"
	"testing"
)

func TestExtractPayloadString(t *testing.T) {
	// Happy path: a real ingest envelope.
	envelope := map[string]interface{}{
		"cluster_id": "c1",
		"kind":       "nodes",
		"payload":    map[string]interface{}{"items": []interface{}{map[string]interface{}{"name": "node-1"}}},
	}
	snapshot := map[string]interface{}{"payload": envelope}

	got := extractPayloadString(snapshot)
	if got == "" {
		t.Fatal("expected payload string, got empty")
	}

	var roundTripped map[string]interface{}
	if err := json.Unmarshal([]byte(got), &roundTripped); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	items, ok := roundTripped["items"].([]interface{})
	if !ok || len(items) != 1 {
		t.Fatalf("expected 1 item, got %v", roundTripped["items"])
	}

	// Missing payload key returns empty.
	if extractPayloadString(map[string]interface{}{}) != "" {
		t.Error("missing payload should return empty string")
	}

	// Non-envelope payload (no inner payload field) returns empty.
	if extractPayloadString(map[string]interface{}{"payload": "raw"}) != "" {
		t.Error("non-envelope payload should return empty string")
	}
}

func TestCountVulnerabilitiesBySeverity(t *testing.T) {
	vulns := []interface{}{
		map[string]interface{}{"Severity": "CRITICAL"},
		map[string]interface{}{"Severity": "CRITICAL"},
		map[string]interface{}{"Severity": "HIGH"},
		map[string]interface{}{"Severity": "MEDIUM"},
		map[string]interface{}{"Severity": "LOW"},
		map[string]interface{}{"Severity": "UNKNOWN"}, // should be ignored
		map[string]interface{}{},                      // no severity, ignored
	}

	counts := countVulnerabilitiesBySeverity(vulns)
	if counts.Critical != 2 {
		t.Errorf("Critical = %d, want 2", counts.Critical)
	}
	if counts.High != 1 {
		t.Errorf("High = %d, want 1", counts.High)
	}
	if counts.Medium != 1 {
		t.Errorf("Medium = %d, want 1", counts.Medium)
	}
	if counts.Low != 1 {
		t.Errorf("Low = %d, want 1", counts.Low)
	}
}

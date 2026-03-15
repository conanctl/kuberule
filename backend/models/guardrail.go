package models

type GuardrailPack struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   GuardrailMetadata `json:"metadata"`
	Spec       GuardrailSpec     `json:"spec"`
}

type GuardrailMetadata struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type GuardrailSpec struct {
	Description string           `json:"description"`
	Owner       string           `json:"owner"`
	Scope       GuardrailScope   `json:"scope"`
	Guardrails  []GuardrailEntry `json:"guardrails"`
}

type GuardrailScope struct {
	Clusters      []string `json:"clusters"`
	Namespaces    []string `json:"namespaces"`
	WorkloadKinds []string `json:"workloadKinds"`
}

type GuardrailEntry struct {
	ID              string               `json:"id"`
	Title           string               `json:"title"`
	Category        string               `json:"category"`
	Severity        string               `json:"severity"`
	Target          string               `json:"target"`
	Check           GuardrailCheck       `json:"check"`
	RemediationHint string               `json:"remediationHint"`
	Rationale       string               `json:"rationale"`
	Exceptions      []GuardrailException `json:"exceptions"`
}

type GuardrailCheck struct {
	Type   string                 `json:"type"`
	Params map[string]interface{} `json:"params"`
}

type GuardrailException struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

func (s *SeverityCounts) Add(other SeverityCounts) {
	s.Critical += other.Critical
	s.High += other.High
	s.Medium += other.Medium
	s.Low += other.Low
}

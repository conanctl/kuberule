package models

type Finding struct {
	ID               int                    `json:"id"`
	GuardrailID      string                 `json:"guardrail_id"`
	Title            string                 `json:"title"`
	Category         string                 `json:"category"`
	Severity         string                 `json:"severity"`
	TargetType       string                 `json:"target_type"`
	TargetIdentifier string                 `json:"target_identifier"`
	ClusterID        string                 `json:"cluster_id"`
	Namespace        string                 `json:"namespace"`
	Status           string                 `json:"status"`
	FirstSeenAt      string                 `json:"first_seen_at"`
	LastSeenAt       string                 `json:"last_seen_at"`
	Evidence         map[string]interface{} `json:"evidence"`
	RemediationHint  string                 `json:"remediation_hint"`
	OwnerLabelValue  string                 `json:"owner_label_value"`
}

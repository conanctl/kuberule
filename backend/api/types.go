package api

// Response shapes shared across handlers. Keep JSON tags aligned with the
// frontend's expectations in frontend/lib/types.ts — the dashboard parses
// these directly.

type healthResponse struct {
	Status string `json:"status"`
}

type ingestRequest struct {
	ClusterID string `json:"cluster_id"`
	Kind      string `json:"kind"`
}

type ingestResponse struct {
	Status    string `json:"status"`
	ClusterID string `json:"cluster_id"`
	Kind      string `json:"kind"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type reloadResponse struct {
	Status string `json:"status"`
}

type updatedResponse struct {
	Status string `json:"status"`
}

type clustersResponse struct {
	Clusters []string `json:"clusters"`
}

type updateFindingRequest struct {
	FindingID int    `json:"finding_id"`
	Status    string `json:"status"`
}

type metricsResponse struct {
	ClusterID            string                   `json:"cluster_id"`
	HealthScore          int                      `json:"health_score"`
	CompliancePct        float64                  `json:"compliance_pct"`
	TotalFindings        int                      `json:"total_findings"`
	OpenFindings         int                      `json:"open_findings"`
	AcknowledgedFindings int                      `json:"acknowledged_findings"`
	ResolvedFindings     int                      `json:"resolved_findings"`
	ActiveGuardrails     int                      `json:"active_guardrails"`
	BySeverity           map[string]int           `json:"by_severity"`
	ByCategory           map[string]int           `json:"by_category"`
	ByOwner              []map[string]interface{} `json:"by_owner"`
	PerCluster           []map[string]interface{} `json:"per_cluster,omitempty"`
}

type metricsHistoryResponse struct {
	ClusterID string                   `json:"cluster_id"`
	History   []map[string]interface{} `json:"history"`
}

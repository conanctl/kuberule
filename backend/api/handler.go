package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"

	"kuberule/backend/derived"
	"kuberule/backend/guardrails"
	"kuberule/backend/storage"
)

func SetupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/health", corsMiddleware(HealthCheck))
	mux.HandleFunc("POST /ingest", corsMiddleware(IngestHandler))
	mux.HandleFunc("GET /guardrails", corsMiddleware(GuardrailsHandler))
	mux.HandleFunc("POST /guardrails/reload", corsMiddleware(ReloadGuardrailsHandler))
	mux.HandleFunc("GET /guardrails/evaluate", corsMiddleware(EvaluateGuardrailsHandler))
	mux.HandleFunc("GET /findings", corsMiddleware(FindingsHandler))
	mux.HandleFunc("POST /findings", corsMiddleware(UpdateFindingHandler))
	mux.HandleFunc("GET /cluster/state", corsMiddleware(DerivedHandler))
	mux.HandleFunc("GET /cluster/raw", corsMiddleware(RawHandler))
	mux.HandleFunc("GET /debug/derived", corsMiddleware(DerivedHandler))
	mux.HandleFunc("GET /debug/raw", corsMiddleware(RawHandler))
	mux.HandleFunc("GET /image-risk-map", corsMiddleware(ImageRiskMapHandler))
	mux.HandleFunc("GET /scans", corsMiddleware(ScansHandler))
	mux.HandleFunc("GET /clusters", corsMiddleware(ClustersHandler))
	mux.HandleFunc("GET /metrics", corsMiddleware(MetricsHandler))
	mux.HandleFunc("GET /metrics/history", corsMiddleware(MetricsHistoryHandler))
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("encode response: %v", err)
	}
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}

func HealthCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{Status: "ok"})
}

func IngestHandler(w http.ResponseWriter, r *http.Request) {
	var raw bytes.Buffer
	var req ingestRequest
	if err := json.NewDecoder(io.TeeReader(r.Body, &raw)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.ClusterID == "" || req.Kind == "" {
		writeErr(w, http.StatusBadRequest, "missing cluster_id or kind")
		return
	}

	if err := storage.InsertSnapshot(req.ClusterID, req.Kind, raw.String()); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, ingestResponse{
		Status:    "ingested",
		ClusterID: req.ClusterID,
		Kind:      req.Kind,
	})
}

func GuardrailsHandler(w http.ResponseWriter, r *http.Request) {
	packs, err := storage.FetchGuardrailPacks()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, packs)
}

func ReloadGuardrailsHandler(w http.ResponseWriter, r *http.Request) {
	if err := guardrails.LoadGuardrailsFromDisk(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, reloadResponse{Status: "reloaded"})
}

func FindingsHandler(w http.ResponseWriter, r *http.Request) {
	filters := map[string]string{
		"status":     r.URL.Query().Get("status"),
		"severity":   r.URL.Query().Get("severity"),
		"cluster_id": r.URL.Query().Get("cluster_id"),
		"category":   r.URL.Query().Get("category"),
	}

	findings, err := storage.FetchFindings(filters)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, findings)
}

func UpdateFindingHandler(w http.ResponseWriter, r *http.Request) {
	var req updateFindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.FindingID == 0 || req.Status == "" {
		writeErr(w, http.StatusBadRequest, "missing finding_id or status")
		return
	}

	switch req.Status {
	case "open", "acknowledged", "resolved":
	default:
		writeErr(w, http.StatusBadRequest, "invalid status, must be one of: open, acknowledged, resolved")
		return
	}

	if err := storage.UpdateFindingStatus(req.FindingID, req.Status); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, updatedResponse{Status: "updated"})
}

func DerivedHandler(w http.ResponseWriter, r *http.Request) {
	clusterID := r.URL.Query().Get("cluster_id")
	if clusterID == "" {
		writeErr(w, http.StatusBadRequest, "missing cluster_id query parameter")
		return
	}

	clusterDerived, err := derived.BuildDerived(clusterID)
	if err != nil {
		log.Printf("building derived data: %v", err)
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, clusterDerived)
}

func RawHandler(w http.ResponseWriter, r *http.Request) {
	clusterID := r.URL.Query().Get("cluster_id")
	kind := r.URL.Query().Get("kind")

	if clusterID == "" || kind == "" {
		writeErr(w, http.StatusBadRequest, "missing cluster_id or kind query parameters")
		return
	}

	snapshots, err := storage.FetchSnapshots(clusterID, kind)
	if err != nil {
		log.Printf("fetching snapshots: %v", err)
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, snapshots)
}

func EvaluateGuardrailsHandler(w http.ResponseWriter, r *http.Request) {
	clusterID := r.URL.Query().Get("cluster_id")
	if clusterID == "" {
		writeErr(w, http.StatusBadRequest, "missing cluster_id query parameter")
		return
	}

	evaluator := guardrails.NewEvaluator(storage.DB)
	results, err := evaluator.Evaluate(clusterID)
	if err != nil {
		log.Printf("evaluating guardrails: %v", err)
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, results)
}

func ImageRiskMapHandler(w http.ResponseWriter, r *http.Request) {
	clusterID := r.URL.Query().Get("cluster_id")
	if clusterID == "" {
		clusterID = "default"
	}

	clusterData, err := derived.BuildDerived(clusterID)
	if err != nil {
		log.Printf("building derived data: %v", err)
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	riskMap := make(map[string]interface{}, len(clusterData.Nodes))
	for _, node := range clusterData.Nodes {
		riskMap[node.Name] = map[string]interface{}{
			"used_images":     node.UsedImages,
			"unused_images":   node.UnusedImages,
			"vulnerabilities": node.Vulnerabilities,
		}
	}
	writeJSON(w, http.StatusOK, riskMap)
}

func ScansHandler(w http.ResponseWriter, r *http.Request) {
	clusterID := r.URL.Query().Get("cluster_id")
	if clusterID == "" {
		clusterID = "default"
	}

	scans, err := storage.FetchScanHistory(clusterID, 50)
	if err != nil {
		log.Printf("fetching scan history: %v", err)
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, scans)
}

func ClustersHandler(w http.ResponseWriter, r *http.Request) {
	clusters, err := storage.FetchDistinctClusterIDs()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, clustersResponse{Clusters: clusters})
}

func MetricsHistoryHandler(w http.ResponseWriter, r *http.Request) {
	clusterID := r.URL.Query().Get("cluster_id")
	if clusterID == "" {
		writeErr(w, http.StatusBadRequest, "cluster_id query parameter is required")
		return
	}

	limit := 50
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			limit = n
		}
	}

	history, err := storage.FetchEvaluationHistory(clusterID, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, metricsHistoryResponse{
		ClusterID: clusterID,
		History:   history,
	})
}

func computeHealthScore(critical, high, medium int) int {
	score := 100 - (critical*10 + high*5 + medium)
	if score < 0 {
		return 0
	}
	return score
}

func computeCompliancePct(open, acknowledged, resolved int) float64 {
	total := open + acknowledged + resolved
	if total == 0 {
		return 100.0
	}
	return float64(resolved) / float64(total) * 100.0
}

func MetricsHandler(w http.ResponseWriter, r *http.Request) {
	clusterID := r.URL.Query().Get("cluster_id")

	bySeverity, err := storage.CountFindingsBySeverity(clusterID, "open")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	byCategory, err := storage.CountFindingsByCategory(clusterID, "open")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	byOwner, err := storage.CountFindingsByOwner(clusterID, "open")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	byStatus, err := storage.CountFindingsByStatus(clusterID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	activeGuardrails, err := storage.CountActiveGuardrails()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	open := byStatus["open"]
	acknowledged := byStatus["acknowledged"]
	resolved := byStatus["resolved"]

	resp := metricsResponse{
		ClusterID:            clusterID,
		HealthScore:          computeHealthScore(bySeverity["critical"], bySeverity["high"], bySeverity["medium"]),
		CompliancePct:        computeCompliancePct(open, acknowledged, resolved),
		TotalFindings:        open + acknowledged + resolved,
		OpenFindings:         open,
		AcknowledgedFindings: acknowledged,
		ResolvedFindings:     resolved,
		ActiveGuardrails:     activeGuardrails,
		BySeverity:           bySeverity,
		ByCategory:           byCategory,
		ByOwner:              byOwner,
	}

	if clusterID == "" {
		perCluster, err := storage.ListClusterRiskSummaries()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		resp.PerCluster = perCluster
	}

	writeJSON(w, http.StatusOK, resp)
}

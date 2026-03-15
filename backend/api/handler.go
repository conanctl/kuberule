package api

import (
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

func MetricsHistoryHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	clusterID := r.URL.Query().Get("cluster_id")
	if clusterID == "" {
		http.Error(w, "cluster_id query parameter is required", http.StatusBadRequest)
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"cluster_id": clusterID,
		"history":    history,
	}

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func computeHealthScore(critical int, high int, medium int) int {
	score := 100 - (critical*10 + high*5 + medium*1)
	if score < 0 {
		return 0
	}
	return score
}

func computeCompliancePct(open int, acknowledged int, resolved int) float64 {
	total := open + acknowledged + resolved
	if total == 0 {
		return 100.0
	}
	return float64(resolved) / float64(total) * 100.0
}

func MetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	clusterID := r.URL.Query().Get("cluster_id")

	bySeverity, err := storage.CountFindingsBySeverity(clusterID, "open")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	byCategory, err := storage.CountFindingsByCategory(clusterID, "open")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	byOwner, err := storage.CountFindingsByOwner(clusterID, "open")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	byStatus, err := storage.CountFindingsByStatus(clusterID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	activeGuardrails, err := storage.CountActiveGuardrails()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	critical := bySeverity["critical"]
	high := bySeverity["high"]
	medium := bySeverity["medium"]

	openCount := byStatus["open"]
	acknowledgedCount := byStatus["acknowledged"]
	resolvedCount := byStatus["resolved"]

	healthScore := computeHealthScore(critical, high, medium)
	compliancePct := computeCompliancePct(openCount, acknowledgedCount, resolvedCount)

	totalFindings := openCount + acknowledgedCount + resolvedCount

	response := map[string]interface{}{
		"cluster_id":            clusterID,
		"health_score":          healthScore,
		"compliance_pct":        compliancePct,
		"total_findings":        totalFindings,
		"open_findings":         openCount,
		"acknowledged_findings": acknowledgedCount,
		"resolved_findings":     resolvedCount,
		"active_guardrails":     activeGuardrails,
		"by_severity":           bySeverity,
		"by_category":           byCategory,
		"by_owner":              byOwner,
	}

	if clusterID == "" {
		perCluster, err := storage.ListClusterRiskSummaries()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		response["per_cluster"] = perCluster
	}

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func ClustersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	clusters, err := storage.FetchDistinctClusterIDs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"clusters": clusters,
	}

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]string{
		"status": "ok",
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
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

func IngestHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	var bodyData map[string]interface{}
	err = json.Unmarshal(bodyBytes, &bodyData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	clusterIDValue, clusterIDExists := bodyData["cluster_id"]
	kindValue, kindExists := bodyData["kind"]

	var clusterID string
	var kind string

	if clusterIDExists {
		clusterID, _ = clusterIDValue.(string)
	}

	if kindExists {
		kind, _ = kindValue.(string)
	}

	if clusterID == "" || kind == "" {
		w.WriteHeader(http.StatusBadRequest)
		errorResponse := map[string]string{
			"error": "missing cluster_id or kind",
		}
		err := json.NewEncoder(w).Encode(errorResponse)
		if err != nil {
			return
		}
		return
	}

	if err := storage.InsertSnapshot(clusterID, kind, string(bodyBytes)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	response := map[string]interface{}{
		"status":     "ingested",
		"cluster_id": clusterID,
		"kind":       kind,
	}

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		return
	}
}

func GuardrailsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	guardrailPacks, err := storage.FetchGuardrailPacks()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(guardrailPacks)
	if err != nil {
		return
	}
}

func ReloadGuardrailsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	err := guardrails.LoadGuardrailsFromDisk()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	response := map[string]string{
		"status": "reloaded",
	}

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		return
	}
}

func FindingsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	filters := make(map[string]string)
	filters["status"] = r.URL.Query().Get("status")
	filters["severity"] = r.URL.Query().Get("severity")
	filters["cluster_id"] = r.URL.Query().Get("cluster_id")
	filters["category"] = r.URL.Query().Get("category")

	findings, err := storage.FetchFindings(filters)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(findings)
	if err != nil {
		return
	}
}

func UpdateFindingHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	var bodyData map[string]interface{}
	err = json.Unmarshal(bodyBytes, &bodyData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	findingIDValue, findingIDExists := bodyData["finding_id"]
	statusValue, statusExists := bodyData["status"]

	if !findingIDExists || !statusExists {
		w.WriteHeader(http.StatusBadRequest)
		errorResponse := map[string]string{
			"error": "missing finding_id or status",
		}
		err := json.NewEncoder(w).Encode(errorResponse)
		if err != nil {
			return
		}
		return
	}

	findingID := int(findingIDValue.(float64))
	status := statusValue.(string)

	allowedStatuses := map[string]bool{
		"open":         true,
		"acknowledged": true,
		"resolved":     true,
	}

	if !allowedStatuses[status] {
		w.WriteHeader(http.StatusBadRequest)
		errorResponse := map[string]string{
			"error": "invalid status, must be one of: open, acknowledged, resolved",
		}
		err := json.NewEncoder(w).Encode(errorResponse)
		if err != nil {
			return
		}
		return
	}

	if err := storage.UpdateFindingStatus(findingID, status); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	response := map[string]string{
		"status": "updated",
	}

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		return
	}
}

func DerivedHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	clusterID := r.URL.Query().Get("cluster_id")
	if clusterID == "" {
		w.WriteHeader(http.StatusBadRequest)
		errorResponse := map[string]string{
			"error": "missing cluster_id query parameter",
		}
		err := json.NewEncoder(w).Encode(errorResponse)
		if err != nil {
			return
		}
		return
	}

	clusterDerived, err := derived.BuildDerived(clusterID)
	if err != nil {
		log.Printf("Error building derived data for cluster %s: %v", strconv.Quote(clusterID), err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(clusterDerived)
	if err != nil {
		return
	}
}

func RawHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	clusterID := r.URL.Query().Get("cluster_id")
	kind := r.URL.Query().Get("kind")

	if clusterID == "" || kind == "" {
		w.WriteHeader(http.StatusBadRequest)
		errorResponse := map[string]string{
			"error": "missing cluster_id or kind query parameters",
		}
		err := json.NewEncoder(w).Encode(errorResponse)
		if err != nil {
			return
		}
		return
	}

	snapshots, err := storage.FetchSnapshots(clusterID, kind)
	if err != nil {
		log.Printf("Error fetching snapshots for cluster %s kind %s: %v", strconv.Quote(clusterID), strconv.Quote(kind), err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(snapshots)
	if err != nil {
		return
	}
}

func EvaluateGuardrailsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	clusterID := r.URL.Query().Get("cluster_id")
	if clusterID == "" {
		w.WriteHeader(http.StatusBadRequest)
		errorResponse := map[string]string{
			"error": "missing cluster_id query parameter",
		}
		err := json.NewEncoder(w).Encode(errorResponse)
		if err != nil {
			return
		}
		return
	}

	evaluator := guardrails.NewEvaluator(storage.DB)
	evaluationResults, err := evaluator.Evaluate(clusterID)
	if err != nil {
		log.Printf("Error evaluating guardrails for cluster %s: %v", strconv.Quote(clusterID), err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(evaluationResults)
	if err != nil {
		return
	}
}

func ImageRiskMapHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	clusterID := r.URL.Query().Get("cluster_id")
	if clusterID == "" {
		clusterID = "default"
	}

	clusterData, err := derived.BuildDerived(clusterID)
	if err != nil {
		log.Printf("Error building derived data for cluster %s: %v", strconv.Quote(clusterID), err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	riskMap := make(map[string]interface{})

	for _, node := range clusterData.Nodes {
		nodeRisk := make(map[string]interface{})
		nodeRisk["used_images"] = node.UsedImages
		nodeRisk["unused_images"] = node.UnusedImages
		nodeRisk["vulnerabilities"] = node.Vulnerabilities
		riskMap[node.Name] = nodeRisk
	}

	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(riskMap)
	if err != nil {
		log.Printf("Error encoding risk map response: %v", err)
		return
	}
}

func ScansHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	clusterID := r.URL.Query().Get("cluster_id")
	if clusterID == "" {
		clusterID = "default"
	}

	scans, err := storage.FetchScanHistory(clusterID, 50)
	if err != nil {
		log.Printf("Error fetching scan history for cluster %s: %v", strconv.Quote(clusterID), err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(scans)
	if err != nil {
		log.Printf("Error encoding scans response: %v", err)
		return
	}
}

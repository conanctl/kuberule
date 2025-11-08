package api

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"kuberule/backend/derived"
	"kuberule/backend/guardrails"
	"kuberule/backend/storage"
)

func SetupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/health", corsMiddleware(HealthCheck))
	mux.HandleFunc("POST /ingest", corsMiddleware(IngestHandler))
	mux.HandleFunc("GET /guardrails", corsMiddleware(GuardrailsHandler))
	mux.HandleFunc("POST /guardrails/reload", corsMiddleware(ReloadGuardrailsHandler))
	mux.HandleFunc("GET /findings", corsMiddleware(FindingsHandler))
	mux.HandleFunc("POST /findings", corsMiddleware(UpdateFindingHandler))
	mux.HandleFunc("GET /debug/derived", corsMiddleware(DerivedHandler))
	mux.HandleFunc("GET /debug/raw", corsMiddleware(RawHandler))
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

	payload := string(bodyBytes)

	storageErr := storage.InsertSnapshot(clusterID, kind, payload)
	if storageErr != nil {
		http.Error(w, storageErr.Error(), http.StatusInternalServerError)
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

	updateErr := storage.UpdateFindingStatus(findingID, status)
	if updateErr != nil {
		http.Error(w, updateErr.Error(), http.StatusInternalServerError)
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
		log.Printf("Error building derived data for cluster %s: %v\n", clusterID, err)
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
		log.Printf("Error fetching snapshots for cluster %s kind %s: %v\n", clusterID, kind, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(snapshots)
	if err != nil {
		return
	}
}

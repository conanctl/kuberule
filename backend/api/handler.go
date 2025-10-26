package api

import (
	"encoding/json"
	"io"
	"net/http"

	"kuberule/backend/guardrails"
	"kuberule/backend/storage"
)

func SetupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/health", corsMiddleware(HealthCheck))
	mux.HandleFunc("POST /ingest", corsMiddleware(IngestHandler))
	mux.HandleFunc("GET /guardrails", corsMiddleware(GuardrailsHandler))
	mux.HandleFunc("POST /guardrails/reload", corsMiddleware(ReloadGuardrailsHandler))
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

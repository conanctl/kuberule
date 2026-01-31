package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"
)

var DB *sql.DB

func InitDB() {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "postgres://user:pass@localhost/kuberule?sslmode=disable"
	}

	var err error
	DB, err = sql.Open("postgres", databaseURL)
	if err != nil {
		log.Println("Warning: Could not open database connection:", err)
		return
	}

	err = DB.Ping()
	if err != nil {
		log.Println("Warning: Could not connect to database:", err)
		DB = nil
		return
	}

	log.Println("Connected to database")

	createTables()
}

func createTables() {
	scanResultsQuery := `
		CREATE TABLE IF NOT EXISTS scan_results (
			id SERIAL PRIMARY KEY,
			received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			cluster_id TEXT,
			kind TEXT,
			payload JSONB
		)
	`

	_, err := DB.Exec(scanResultsQuery)
	if err != nil {
		log.Fatal(err)
	}

	guardrailPacksQuery := `
		CREATE TABLE IF NOT EXISTS guardrail_packs (
			id SERIAL PRIMARY KEY,
			name TEXT,
			version TEXT,
			loaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			pack JSONB
		)
	`

	_, err = DB.Exec(guardrailPacksQuery)
	if err != nil {
		log.Fatal(err)
	}

	findingsQuery := `
		CREATE TABLE IF NOT EXISTS findings (
			id SERIAL PRIMARY KEY,
			guardrail_id TEXT,
			title TEXT,
			category TEXT,
			severity TEXT,
			target_type TEXT,
			target_identifier TEXT,
			cluster_id TEXT,
			namespace TEXT,
			status TEXT DEFAULT 'open',
			first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			evidence JSONB,
			remediation_hint TEXT,
			owner_label_value TEXT,
			UNIQUE(guardrail_id, target_identifier)
		)
	`

	_, err = DB.Exec(findingsQuery)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Tables created")
}

func InsertSnapshot(clusterID string, kind string, payload string) error {
	query := "INSERT INTO scan_results (cluster_id, kind, payload) VALUES ($1, $2, $3)"

	_, err := DB.Exec(query, clusterID, kind, payload)
	if err != nil {
		return err
	}

	return nil
}

func FetchSnapshots(clusterID string, kind string) ([]map[string]interface{}, error) {
	query := "SELECT id, received_at, cluster_id, kind, payload FROM scan_results WHERE cluster_id=$1 AND kind=$2 ORDER BY received_at DESC"

	rows, err := DB.Query(query, clusterID, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}

	for rows.Next() {
		var id int
		var receivedAt string
		var clusterIDResult string
		var kindResult string
		var payloadBytes []byte

		err := rows.Scan(&id, &receivedAt, &clusterIDResult, &kindResult, &payloadBytes)
		if err != nil {
			return nil, err
		}

		var payloadJSON interface{}
		err = json.Unmarshal(payloadBytes, &payloadJSON)
		if err != nil {
			return nil, err
		}

		result := map[string]interface{}{
			"id":          id,
			"received_at": receivedAt,
			"cluster_id":  clusterIDResult,
			"kind":        kindResult,
			"payload":     payloadJSON,
		}

		results = append(results, result)
	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return results, nil
}

func InsertGuardrailPack(name string, version string, packJSON string) error {
	query := "INSERT INTO guardrail_packs (name, version, pack) VALUES ($1, $2, $3)"

	_, err := DB.Exec(query, name, version, packJSON)
	if err != nil {
		return err
	}

	return nil
}

func FetchGuardrailPacks() ([]map[string]interface{}, error) {
	query := "SELECT id, name, version, loaded_at, pack FROM guardrail_packs ORDER BY loaded_at DESC"

	rows, err := DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}

	for rows.Next() {
		var id int
		var name string
		var version string
		var loadedAt string
		var packBytes []byte

		err := rows.Scan(&id, &name, &version, &loadedAt, &packBytes)
		if err != nil {
			return nil, err
		}

		var packJSON interface{}
		err = json.Unmarshal(packBytes, &packJSON)
		if err != nil {
			return nil, err
		}

		result := map[string]interface{}{
			"id":        id,
			"name":      name,
			"version":   version,
			"loaded_at": loadedAt,
			"pack":      packJSON,
		}

		results = append(results, result)
	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return results, nil
}

func DeleteGuardrailPack(name string) error {
	query := "DELETE FROM guardrail_packs WHERE name=$1"

	_, err := DB.Exec(query, name)
	if err != nil {
		return err
	}

	return nil
}

func UpsertFinding(finding map[string]interface{}) error {
	guardrailID := finding["guardrail_id"].(string)
	title := finding["title"].(string)
	category := finding["category"].(string)
	severity := finding["severity"].(string)
	targetType := finding["target_type"].(string)
	targetIdentifier := finding["target_identifier"].(string)
	clusterID := finding["cluster_id"].(string)
	namespace := finding["namespace"].(string)
	status := finding["status"].(string)
	remediationHint := finding["remediation_hint"].(string)
	ownerLabelValue := finding["owner_label_value"].(string)

	evidenceMap, ok := finding["evidence"].(map[string]interface{})
	if !ok {
		evidenceMap = make(map[string]interface{})
	}

	evidenceJSON, err := json.Marshal(evidenceMap)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO findings (guardrail_id, title, category, severity, target_type, target_identifier, cluster_id, namespace, status, evidence, remediation_hint, owner_label_value)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (guardrail_id, target_identifier)
		DO UPDATE SET last_seen_at=CURRENT_TIMESTAMP, evidence=$10
	`

	_, err = DB.Exec(query, guardrailID, title, category, severity, targetType, targetIdentifier, clusterID, namespace, status, string(evidenceJSON), remediationHint, ownerLabelValue)
	if err != nil {
		return err
	}

	return nil
}

func FetchFindings(filters map[string]string) ([]map[string]interface{}, error) {
	query := "SELECT id, guardrail_id, title, category, severity, target_type, target_identifier, cluster_id, namespace, status, first_seen_at, last_seen_at, evidence, remediation_hint, owner_label_value FROM findings WHERE 1=1"

	args := []interface{}{}
	argIndex := 1

	if status, exists := filters["status"]; exists && status != "" {
		query += " AND status=$" + fmt.Sprintf("%d", argIndex)
		args = append(args, status)
		argIndex++
	}

	if severity, exists := filters["severity"]; exists && severity != "" {
		query += " AND severity=$" + fmt.Sprintf("%d", argIndex)
		args = append(args, severity)
		argIndex++
	}

	if clusterID, exists := filters["cluster_id"]; exists && clusterID != "" {
		query += " AND cluster_id=$" + fmt.Sprintf("%d", argIndex)
		args = append(args, clusterID)
		argIndex++
	}

	if category, exists := filters["category"]; exists && category != "" {
		query += " AND category=$" + fmt.Sprintf("%d", argIndex)
		args = append(args, category)
	}

	query += " ORDER BY last_seen_at DESC"

	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}

	for rows.Next() {
		var id int
		var guardrailID string
		var title string
		var category string
		var severity string
		var targetType string
		var targetIdentifier string
		var clusterID string
		var namespace string
		var status string
		var firstSeenAt string
		var lastSeenAt string
		var evidenceBytes []byte
		var remediationHint string
		var ownerLabelValue string

		err := rows.Scan(&id, &guardrailID, &title, &category, &severity, &targetType, &targetIdentifier, &clusterID, &namespace, &status, &firstSeenAt, &lastSeenAt, &evidenceBytes, &remediationHint, &ownerLabelValue)
		if err != nil {
			return nil, err
		}

		var evidenceJSON interface{}
		err = json.Unmarshal(evidenceBytes, &evidenceJSON)
		if err != nil {
			return nil, err
		}

		result := map[string]interface{}{
			"id":                id,
			"guardrail_id":      guardrailID,
			"title":             title,
			"category":          category,
			"severity":          severity,
			"target_type":       targetType,
			"target_identifier": targetIdentifier,
			"cluster_id":        clusterID,
			"namespace":         namespace,
			"status":            status,
			"first_seen_at":     firstSeenAt,
			"last_seen_at":      lastSeenAt,
			"evidence":          evidenceJSON,
			"remediation_hint":  remediationHint,
			"owner_label_value": ownerLabelValue,
		}

		results = append(results, result)
	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return results, nil
}

func UpdateFindingStatus(findingID int, status string) error {
	query := "UPDATE findings SET status=$1 WHERE id=$2"

	_, err := DB.Exec(query, status, findingID)
	if err != nil {
		return err
	}

	return nil
}

func FetchScanHistory(clusterID string, limit int) ([]map[string]interface{}, error) {
	query := `
		SELECT id, received_at, cluster_id, kind
		FROM scan_results
		WHERE cluster_id = $1
		ORDER BY received_at DESC
		LIMIT $2
	`

	rows, err := DB.Query(query, clusterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []map[string]interface{}

	for rows.Next() {
		var id int
		var receivedAt time.Time
		var scanClusterID string
		var kind string

		err := rows.Scan(&id, &receivedAt, &scanClusterID, &kind)
		if err != nil {
			continue
		}

		scan := map[string]interface{}{
			"id":          id,
			"received_at": receivedAt.Format(time.RFC3339),
			"cluster_id":  scanClusterID,
			"kind":        kind,
		}
		scans = append(scans, scan)
	}

	rowsErr := rows.Err()
	if rowsErr != nil {
		return nil, rowsErr
	}

	return scans, nil
}

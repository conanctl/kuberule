package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/lib/pq"
)

var DB *sql.DB

func InitDB() {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "postgres://localhost/kuberule?sslmode=disable"
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

	alterFindingsQuery := `
		ALTER TABLE findings
		ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP NULL
	`

	_, err = DB.Exec(alterFindingsQuery)
	if err != nil {
		log.Fatal(err)
	}

	evaluationRunsQuery := `
		CREATE TABLE IF NOT EXISTS evaluation_runs (
			id SERIAL PRIMARY KEY,
			cluster_id TEXT NOT NULL,
			ran_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			total_findings INT,
			open_findings INT,
			resolved_findings INT,
			critical INT,
			high INT,
			medium INT,
			low INT,
			health_score INT,
			compliance_pct DOUBLE PRECISION
		)
	`

	_, err = DB.Exec(evaluationRunsQuery)
	if err != nil {
		log.Fatal(err)
	}

	evaluationRunsIndexQuery := `
		CREATE INDEX IF NOT EXISTS evaluation_runs_cluster_ran_at
		ON evaluation_runs (cluster_id, ran_at DESC)
	`

	_, err = DB.Exec(evaluationRunsIndexQuery)
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
		DO UPDATE SET
			last_seen_at=CURRENT_TIMESTAMP,
			evidence=$10,
			severity=$4,
			title=$2,
			remediation_hint=$11,
			namespace=$8,
			owner_label_value=$12
	`

	_, err = DB.Exec(query, guardrailID, title, category, severity, targetType, targetIdentifier, clusterID, namespace, status, string(evidenceJSON), remediationHint, ownerLabelValue)
	if err != nil {
		return err
	}

	return nil
}

func FetchFindings(filters map[string]string) ([]map[string]interface{}, error) {
	var query strings.Builder
	query.WriteString("SELECT id, guardrail_id, title, category, severity, target_type, target_identifier, cluster_id, namespace, status, first_seen_at, last_seen_at, resolved_at, evidence, remediation_hint, owner_label_value FROM findings WHERE 1=1")

	args := []interface{}{}
	argIndex := 1

	if status, exists := filters["status"]; exists && status != "" {
		fmt.Fprintf(&query, " AND status=$%d", argIndex)
		args = append(args, status)
		argIndex++
	}

	if severity, exists := filters["severity"]; exists && severity != "" {
		fmt.Fprintf(&query, " AND severity=$%d", argIndex)
		args = append(args, severity)
		argIndex++
	}

	if clusterID, exists := filters["cluster_id"]; exists && clusterID != "" {
		fmt.Fprintf(&query, " AND cluster_id=$%d", argIndex)
		args = append(args, clusterID)
		argIndex++
	}

	if category, exists := filters["category"]; exists && category != "" {
		fmt.Fprintf(&query, " AND category=$%d", argIndex)
		args = append(args, category)
	}

	query.WriteString(" ORDER BY last_seen_at DESC")

	rows, err := DB.Query(query.String(), args...)
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
		var resolvedAt sql.NullString
		var evidenceBytes []byte
		var remediationHint string
		var ownerLabelValue string

		err := rows.Scan(&id, &guardrailID, &title, &category, &severity, &targetType, &targetIdentifier, &clusterID, &namespace, &status, &firstSeenAt, &lastSeenAt, &resolvedAt, &evidenceBytes, &remediationHint, &ownerLabelValue)
		if err != nil {
			return nil, err
		}

		var evidenceJSON interface{}
		err = json.Unmarshal(evidenceBytes, &evidenceJSON)
		if err != nil {
			return nil, err
		}

		var resolvedAtValue interface{}
		if resolvedAt.Valid {
			resolvedAtValue = resolvedAt.String
		} else {
			resolvedAtValue = nil
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
			"resolved_at":       resolvedAtValue,
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
	query := `
		UPDATE findings
		SET status = $1,
		    resolved_at = CASE
		        WHEN $1 = 'resolved' THEN CURRENT_TIMESTAMP
		        ELSE NULL
		    END
		WHERE id = $2
	`

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

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return scans, nil
}

func FetchDistinctClusterIDs() ([]string, error) {
	query := "SELECT DISTINCT cluster_id FROM scan_results ORDER BY cluster_id"

	rows, err := DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	clusterIDs := []string{}

	for rows.Next() {
		var clusterID string
		err := rows.Scan(&clusterID)
		if err != nil {
			return nil, err
		}
		clusterIDs = append(clusterIDs, clusterID)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return clusterIDs, nil
}

func CountFindingsBySeverity(clusterID string, status string) (map[string]int, error) {
	counts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}

	var query string
	var args []interface{}

	if clusterID != "" {
		query = "SELECT severity, COUNT(*) FROM findings WHERE cluster_id = $1 AND status = $2 GROUP BY severity"
		args = []interface{}{clusterID, status}
	} else {
		query = "SELECT severity, COUNT(*) FROM findings WHERE status = $1 GROUP BY severity"
		args = []interface{}{status}
	}

	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var severity string
		var count int

		err := rows.Scan(&severity, &count)
		if err != nil {
			return nil, err
		}

		counts[severity] = count
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return counts, nil
}

func CountFindingsByCategory(clusterID string, status string) (map[string]int, error) {
	counts := map[string]int{}

	var query string
	var args []interface{}

	if clusterID != "" {
		query = "SELECT category, COUNT(*) FROM findings WHERE cluster_id = $1 AND status = $2 GROUP BY category"
		args = []interface{}{clusterID, status}
	} else {
		query = "SELECT category, COUNT(*) FROM findings WHERE status = $1 GROUP BY category"
		args = []interface{}{status}
	}

	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var category string
		var count int

		err := rows.Scan(&category, &count)
		if err != nil {
			return nil, err
		}

		counts[category] = count
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return counts, nil
}

func CountFindingsByStatus(clusterID string) (map[string]int, error) {
	counts := map[string]int{
		"open":         0,
		"acknowledged": 0,
		"resolved":     0,
	}

	var query string
	var args []interface{}

	if clusterID != "" {
		query = "SELECT status, COUNT(*) FROM findings WHERE cluster_id = $1 GROUP BY status"
		args = []interface{}{clusterID}
	} else {
		query = "SELECT status, COUNT(*) FROM findings GROUP BY status"
		args = []interface{}{}
	}

	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int

		err := rows.Scan(&status, &count)
		if err != nil {
			return nil, err
		}

		counts[status] = count
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return counts, nil
}

func CountFindingsByOwner(clusterID string, status string) ([]map[string]interface{}, error) {
	var query string
	var args []interface{}

	if clusterID != "" {
		query = `
			SELECT COALESCE(owner_label_value, '') AS owner, severity, COUNT(*)
			FROM findings
			WHERE cluster_id = $1 AND status = $2
			GROUP BY owner, severity
		`
		args = []interface{}{clusterID, status}
	} else {
		query = `
			SELECT COALESCE(owner_label_value, '') AS owner, severity, COUNT(*)
			FROM findings
			WHERE status = $1
			GROUP BY owner, severity
		`
		args = []interface{}{status}
	}

	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ownerMap := map[string]map[string]int{}

	for rows.Next() {
		var owner string
		var severity string
		var count int

		err := rows.Scan(&owner, &severity, &count)
		if err != nil {
			return nil, err
		}

		if _, exists := ownerMap[owner]; !exists {
			ownerMap[owner] = map[string]int{
				"critical": 0,
				"high":     0,
				"medium":   0,
				"low":      0,
				"total":    0,
			}
		}

		ownerMap[owner][severity] = count
		ownerMap[owner]["total"] += count
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	result := []map[string]interface{}{}
	for owner, counts := range ownerMap {
		result = append(result, map[string]interface{}{
			"owner":    owner,
			"critical": counts["critical"],
			"high":     counts["high"],
			"medium":   counts["medium"],
			"low":      counts["low"],
			"total":    counts["total"],
		})
	}

	return result, nil
}

func ListClusterRiskSummaries() ([]map[string]interface{}, error) {
	query := `
		SELECT cluster_id, severity, COUNT(*)
		FROM findings
		WHERE status = 'open'
		GROUP BY cluster_id, severity
	`

	rows, err := DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	clusterMap := map[string]map[string]int{}

	for rows.Next() {
		var clusterID string
		var severity string
		var count int

		err := rows.Scan(&clusterID, &severity, &count)
		if err != nil {
			return nil, err
		}

		if _, exists := clusterMap[clusterID]; !exists {
			clusterMap[clusterID] = map[string]int{
				"critical": 0,
				"high":     0,
				"medium":   0,
				"low":      0,
			}
		}

		clusterMap[clusterID][severity] = count
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	result := []map[string]interface{}{}
	for clusterID, counts := range clusterMap {
		critical := counts["critical"]
		high := counts["high"]
		medium := counts["medium"]
		low := counts["low"]

		riskScore := float64(critical)*4.0 + float64(high)*2.0 + float64(medium)*1.0 + float64(low)*0.5
		openCount := critical + high + medium + low

		healthScore := 100 - (critical*10 + high*5 + medium*1)
		if healthScore < 0 {
			healthScore = 0
		}

		result = append(result, map[string]interface{}{
			"cluster_id":   clusterID,
			"health_score": healthScore,
			"open":         openCount,
			"risk_score":   riskScore,
		})
	}

	return result, nil
}

func AutoResolveFindings(clusterID string, seenKeys []string) (int, error) {
	if clusterID == "" {
		return 0, fmt.Errorf("cluster_id is required for auto-resolve")
	}

	query := `
		UPDATE findings
		SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP
		WHERE cluster_id = $1
		  AND status IN ('open', 'acknowledged')
		  AND NOT ((guardrail_id || '|' || target_identifier) = ANY($2::text[]))
	`

	result, err := DB.Exec(query, clusterID, pq.Array(seenKeys))
	if err != nil {
		return 0, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	return int(rowsAffected), nil
}

func ReopenResolvedFinding(guardrailID string, targetIdentifier string) error {
	query := `
		UPDATE findings
		SET status = 'open', resolved_at = NULL
		WHERE guardrail_id = $1
		  AND target_identifier = $2
		  AND status = 'resolved'
	`

	_, err := DB.Exec(query, guardrailID, targetIdentifier)
	return err
}

func InsertEvaluationRun(clusterID string, totalFindings int, openFindings int, resolvedFindings int, critical int, high int, medium int, low int, healthScore int, compliancePct float64) error {
	query := `
		INSERT INTO evaluation_runs (cluster_id, total_findings, open_findings, resolved_findings, critical, high, medium, low, health_score, compliance_pct)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	_, err := DB.Exec(query, clusterID, totalFindings, openFindings, resolvedFindings, critical, high, medium, low, healthScore, compliancePct)
	return err
}

func FetchEvaluationHistory(clusterID string, limit int) ([]map[string]interface{}, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	query := `
		SELECT ran_at, total_findings, open_findings, resolved_findings, critical, high, medium, low, health_score, compliance_pct
		FROM evaluation_runs
		WHERE cluster_id = $1
		ORDER BY ran_at DESC
		LIMIT $2
	`

	rows, err := DB.Query(query, clusterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	history := []map[string]interface{}{}

	for rows.Next() {
		var ranAt time.Time
		var totalFindings, openFindings, resolvedFindings int
		var critical, high, medium, low int
		var healthScore int
		var compliancePct float64

		err := rows.Scan(&ranAt, &totalFindings, &openFindings, &resolvedFindings, &critical, &high, &medium, &low, &healthScore, &compliancePct)
		if err != nil {
			return nil, err
		}

		entry := map[string]interface{}{
			"ran_at":            ranAt.Format(time.RFC3339),
			"total_findings":    totalFindings,
			"open_findings":     openFindings,
			"resolved_findings": resolvedFindings,
			"critical":          critical,
			"high":              high,
			"medium":            medium,
			"low":               low,
			"health_score":      healthScore,
			"compliance_pct":    compliancePct,
		}

		history = append(history, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i, j := 0, len(history)-1; i < j; i, j = i+1, j-1 {
		history[i], history[j] = history[j], history[i]
	}

	return history, nil
}

func CountActiveGuardrails() (int, error) {
	packs, err := FetchGuardrailPacks()
	if err != nil {
		return 0, err
	}

	total := 0

	for _, packData := range packs {
		packValue, hasPack := packData["pack"]
		if !hasPack {
			continue
		}

		packMap, isMap := packValue.(map[string]interface{})
		if !isMap {
			continue
		}

		specValue, hasSpec := packMap["spec"]
		if !hasSpec {
			continue
		}

		specMap, isSpecMap := specValue.(map[string]interface{})
		if !isSpecMap {
			continue
		}

		guardrailsValue, hasGuardrails := specMap["guardrails"]
		if !hasGuardrails {
			continue
		}

		guardrailsList, isList := guardrailsValue.([]interface{})
		if !isList {
			continue
		}

		total += len(guardrailsList)
	}

	return total, nil
}

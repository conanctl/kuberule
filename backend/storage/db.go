package storage

import (
	"database/sql"
	"encoding/json"
	"log"
	"os"

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

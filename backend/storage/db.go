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
	query := `
		CREATE TABLE IF NOT EXISTS scan_results (
			id SERIAL PRIMARY KEY,
			received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			cluster_id TEXT,
			kind TEXT,
			payload JSONB
		)
	`

	_, err := DB.Exec(query)
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

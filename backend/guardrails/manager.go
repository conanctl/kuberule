package guardrails

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"kuberule/backend/models"
	"kuberule/backend/storage"
)

func LoadGuardrailsFromDisk() error {
	packsDir := os.Getenv("GUARDRAILS_DIR")
	if packsDir == "" {
		packsDir = "backend/guardrails/packs"
	}

	entries, err := os.ReadDir(packsDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			continue
		}

		if filepath.Base(name) != name {
			continue
		}
		path := filepath.Join(packsDir, name)
		pack, err := readPack(path, ext)
		if err != nil {
			return fmt.Errorf("read pack %s: %w", name, err)
		}

		packJSON, err := json.Marshal(pack)
		if err != nil {
			return fmt.Errorf("marshal pack %s: %w", name, err)
		}

		if err := storage.DeleteGuardrailPack(pack.Metadata.Name); err != nil {
			log.Printf("delete stale pack %s: %v", pack.Metadata.Name, err)
		}

		if err := storage.InsertGuardrailPack(pack.Metadata.Name, pack.Metadata.Version, string(packJSON)); err != nil {
			return err
		}

		log.Printf("loaded guardrail pack: %s", pack.Metadata.Name)
	}

	return nil
}

func readPack(path, ext string) (models.GuardrailPack, error) {
	var pack models.GuardrailPack

	data, err := os.ReadFile(path) // #nosec G304,G703 -- filename validated in LoadGuardrailsFromDisk
	if err != nil {
		return pack, err
	}

	switch ext {
	case ".yaml", ".yml":
		var raw interface{}
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return pack, err
		}
		jsonBytes, err := json.Marshal(yamlToJSON(raw))
		if err != nil {
			return pack, err
		}
		if err := json.Unmarshal(jsonBytes, &pack); err != nil {
			return pack, err
		}
	case ".json":
		if err := json.Unmarshal(data, &pack); err != nil {
			return pack, err
		}
	}

	return pack, nil
}

func yamlToJSON(v interface{}) interface{} {
	switch typed := v.(type) {
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(typed))
		for k, val := range typed {
			out[fmt.Sprintf("%v", k)] = yamlToJSON(val)
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(typed))
		for k, val := range typed {
			out[k] = yamlToJSON(val)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(typed))
		for i, val := range typed {
			out[i] = yamlToJSON(val)
		}
		return out
	default:
		return v
	}
}

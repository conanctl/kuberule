package guardrails

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"

	"kuberule/backend/models"
	"kuberule/backend/storage"
)

func LoadGuardrailsFromDisk() error {
	packsDir := os.Getenv("GUARDRAILS_DIR")
	if packsDir == "" {
		packsDir = "backend/guardrails/packs"
	}

	yamlPattern := filepath.Join(packsDir, "*.yaml")
	jsonPattern := filepath.Join(packsDir, "*.json")

	yamlFiles, err := filepath.Glob(yamlPattern)
	if err != nil {
		return err
	}

	jsonFiles, err := filepath.Glob(jsonPattern)
	if err != nil {
		return err
	}

	allFiles := append(yamlFiles, jsonFiles...)

	for _, filePath := range allFiles {
		fileBytes, err := os.ReadFile(filePath) // #nosec G304
		if err != nil {
			return err
		}

		var guardrailPack models.GuardrailPack
		err = json.Unmarshal(fileBytes, &guardrailPack)
		if err != nil {
			return err
		}

		packJSON, err := json.Marshal(guardrailPack)
		if err != nil {
			return err
		}

		packJSONString := string(packJSON)

		err = storage.InsertGuardrailPack(guardrailPack.Metadata.Name, guardrailPack.Metadata.Version, packJSONString)
		if err != nil {
			return err
		}

		log.Printf("Loaded guardrail pack: %s\n", guardrailPack.Metadata.Name)
	}

	return nil
}

package guardrails

import (
	"database/sql"
	"encoding/json"
	"log"

	"kuberule/backend/derived"
	"kuberule/backend/models"
	"kuberule/backend/storage"
)

type Evaluator struct {
	DB *sql.DB
}

func NewEvaluator(db *sql.DB) *Evaluator {
	return &Evaluator{DB: db}
}

func (e *Evaluator) Evaluate(clusterID string) ([]map[string]interface{}, error) {
	guardrailPacksData, err := storage.FetchGuardrailPacks()
	if err != nil {
		log.Printf("Error fetching guardrail packs: %v\n", err)
		return nil, err
	}

	clusterDerived, err := derived.BuildDerived(clusterID)
	if err != nil {
		log.Printf("Error building derived data for cluster %s: %v\n", clusterID, err)
		return nil, err
	}

	results := make([]map[string]interface{}, 0)

	for _, packData := range guardrailPacksData {
		packInterface, haspack := packData["pack"]
		if !haspack {
			log.Printf("Warning: guardrail pack missing pack field\n")
			continue
		}

		packJsonBytes, err := json.Marshal(packInterface)
		if err != nil {
			log.Printf("Error marshaling pack: %v\n", err)
			continue
		}

		var guardrailPack models.GuardrailPack
		err = json.Unmarshal(packJsonBytes, &guardrailPack)
		if err != nil {
			log.Printf("Error unmarshaling guardrail pack: %v\n", err)
			continue
		}

		for _, guardrailEntry := range guardrailPack.Spec.Guardrails {
			targets := e.collectTargets(guardrailEntry, clusterDerived)

			evaluationResult := map[string]interface{}{
				"guardrail_id":     guardrailEntry.ID,
				"title":            guardrailEntry.Title,
				"category":         guardrailEntry.Category,
				"severity":         guardrailEntry.Severity,
				"target":           guardrailEntry.Target,
				"targets_count":    len(targets),
				"check_type":       guardrailEntry.Check.Type,
				"check_params":     guardrailEntry.Check.Params,
				"remediation_hint": guardrailEntry.RemediationHint,
				"rationale":        guardrailEntry.Rationale,
			}

			results = append(results, evaluationResult)
		}
	}

	return results, nil
}

func (e *Evaluator) collectTargets(guardrailEntry models.GuardrailEntry, clusterDerived *derived.ClusterDerived) []interface{} {
	switch guardrailEntry.Target {
	case "image":
		targets := make([]interface{}, 0)
		for index := range clusterDerived.Images {
			targets = append(targets, clusterDerived.Images[index])
		}
		return targets
	case "workload":
		targets := make([]interface{}, 0)
		for index := range clusterDerived.Workloads {
			targets = append(targets, clusterDerived.Workloads[index])
		}
		return targets
	case "node":
		targets := make([]interface{}, 0)
		for index := range clusterDerived.Nodes {
			targets = append(targets, clusterDerived.Nodes[index])
		}
		return targets
	case "namespace":
		targets := make([]interface{}, 0)
		for index := range clusterDerived.Namespaces {
			targets = append(targets, clusterDerived.Namespaces[index])
		}
		return targets
	case "pod":
		targets := make([]interface{}, 0)
		for index := range clusterDerived.Pods {
			targets = append(targets, clusterDerived.Pods[index])
		}
		return targets
	default:
		log.Printf("Warning: unknown target type %s\n", guardrailEntry.Target)
		return make([]interface{}, 0)
	}
}

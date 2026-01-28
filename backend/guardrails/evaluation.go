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

			for _, target := range targets {
				if shouldSkipDueToException(guardrailEntry, target, clusterID) {
					continue
				}
				checkPassed, evidence := e.evaluateCheck(guardrailEntry, target, clusterID)
				if !checkPassed {
					finding := e.createFinding(guardrailEntry, target, clusterID, evidence)
					upsertErr := storage.UpsertFinding(finding)
					if upsertErr != nil {
						log.Printf("Error upserting finding: %v\n", upsertErr)
					}
				}
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

func (e *Evaluator) evaluateCheck(guardrailEntry models.GuardrailEntry, target interface{}, clusterID string) (bool, map[string]interface{}) {
	switch guardrailEntry.Check.Type {
	case "vuln_threshold":
		return e.checkVulnThreshold(target, guardrailEntry.Check.Params)
	case "required_label":
		return e.checkRequiredLabel(target, guardrailEntry.Check.Params)
	case "unused_images_present":
		return e.checkUnusedImages(target, guardrailEntry.Check.Params)
	default:
		log.Printf("Warning: unknown check type %s\n", guardrailEntry.Check.Type)
		return true, make(map[string]interface{})
	}
}

func (e *Evaluator) checkVulnThreshold(target interface{}, params map[string]interface{}) (bool, map[string]interface{}) {
	imageEnriched, ok := target.(derived.ImageEnriched)
	if !ok {
		log.Printf("Warning: target is not ImageEnriched type\n")
		return true, make(map[string]interface{})
	}

	maxCriticalInterface, hasMaxCritical := params["maxCritical"]
	if !hasMaxCritical {
		log.Printf("Warning: maxCritical parameter missing\n")
		return true, make(map[string]interface{})
	}

	maxCriticalFloat, ok := maxCriticalInterface.(float64)
	if !ok {
		log.Printf("Warning: maxCritical is not a number\n")
		return true, make(map[string]interface{})
	}

	maxCritical := int(maxCriticalFloat)

	if imageEnriched.Vulnerabilities.Critical > maxCritical {
		evidence := map[string]interface{}{
			"critical":     imageEnriched.Vulnerabilities.Critical,
			"high":         imageEnriched.Vulnerabilities.High,
			"medium":       imageEnriched.Vulnerabilities.Medium,
			"low":          imageEnriched.Vulnerabilities.Low,
			"max_critical": maxCritical,
		}
		return false, evidence
	}

	return true, make(map[string]interface{})
}

func (e *Evaluator) checkRequiredLabel(target interface{}, params map[string]interface{}) (bool, map[string]interface{}) {
	namespaceEnriched, ok := target.(derived.NamespaceEnriched)
	if !ok {
		log.Printf("Warning: target is not NamespaceEnriched type\n")
		return true, make(map[string]interface{})
	}

	labelKeyInterface, hasLabelKey := params["labelKey"]
	if !hasLabelKey {
		log.Printf("Warning: labelKey parameter missing\n")
		return true, make(map[string]interface{})
	}

	labelKey, ok := labelKeyInterface.(string)
	if !ok {
		log.Printf("Warning: labelKey is not a string\n")
		return true, make(map[string]interface{})
	}

	_, labelExists := namespaceEnriched.Labels[labelKey]
	if !labelExists {
		evidence := map[string]interface{}{
			"missing_label":  labelKey,
			"present_labels": namespaceEnriched.Labels,
		}
		return false, evidence
	}

	return true, make(map[string]interface{})
}

func (e *Evaluator) checkUnusedImages(target interface{}, params map[string]interface{}) (bool, map[string]interface{}) {
	nodeEnriched, ok := target.(derived.NodeEnriched)
	if !ok {
		log.Printf("Warning: target is not NodeEnriched type\n")
		return true, make(map[string]interface{})
	}

	maxUnusedInterface, hasMaxUnused := params["maxUnused"]
	if !hasMaxUnused {
		log.Printf("Warning: maxUnused parameter missing\n")
		return true, make(map[string]interface{})
	}

	maxUnusedFloat, ok := maxUnusedInterface.(float64)
	if !ok {
		log.Printf("Warning: maxUnused is not a number\n")
		return true, make(map[string]interface{})
	}

	maxUnused := int(maxUnusedFloat)

	if len(nodeEnriched.UnusedImages) > maxUnused {
		evidence := map[string]interface{}{
			"unused_count":  len(nodeEnriched.UnusedImages),
			"max_unused":    maxUnused,
			"unused_images": nodeEnriched.UnusedImages,
		}
		return false, evidence
	}

	return true, make(map[string]interface{})
}

func shouldSkipDueToException(guardrail models.GuardrailEntry, target interface{}, clusterID string) bool {
	for _, exception := range guardrail.Exceptions {
		if exception.Type == "namespace" {
			if guardrail.Target == "image" {
				img, ok := target.(derived.ImageEnriched)
				if !ok {
					continue
				}
				for _, workload := range img.UsedBy {
					if workload == exception.Value {
						return true
					}
				}
			} else if guardrail.Target == "workload" {
				wl, ok := target.(derived.WorkloadEnriched)
				if !ok {
					continue
				}
				if wl.Namespace == exception.Value {
					return true
				}
			} else if guardrail.Target == "namespace" {
				ns, ok := target.(derived.NamespaceEnriched)
				if !ok {
					continue
				}
				if ns.Name == exception.Value {
					return true
				}
			}
		}
	}
	return false
}

func (e *Evaluator) createFinding(guardrailEntry models.GuardrailEntry, target interface{}, clusterID string, evidence map[string]interface{}) map[string]interface{} {
	targetIdentifier := ""
	targetType := guardrailEntry.Target
	namespace := ""

	switch t := target.(type) {
	case derived.ImageEnriched:
		targetIdentifier = t.Name
	case derived.WorkloadEnriched:
		targetIdentifier = t.Name
		namespace = t.Namespace
	case derived.NodeEnriched:
		targetIdentifier = t.Name
	case derived.NamespaceEnriched:
		targetIdentifier = t.Name
		namespace = t.Name
	case derived.PodEnriched:
		targetIdentifier = t.Name
		namespace = t.Namespace
	default:
		log.Printf("Warning: unknown target type for finding\n")
		targetIdentifier = "unknown"
	}

	finding := map[string]interface{}{
		"guardrail_id":      guardrailEntry.ID,
		"title":             guardrailEntry.Title,
		"category":          guardrailEntry.Category,
		"severity":          guardrailEntry.Severity,
		"target_type":       targetType,
		"target_identifier": targetIdentifier,
		"cluster_id":        clusterID,
		"namespace":         namespace,
		"status":            "open",
		"evidence":          evidence,
		"remediation_hint":  guardrailEntry.RemediationHint,
		"owner_label_value": "",
	}

	return finding
}

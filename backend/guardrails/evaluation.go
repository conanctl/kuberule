package guardrails

import (
	"database/sql"
	"encoding/json"
	"log"
	"os"

	"kuberule/backend/derived"
	"kuberule/backend/models"
	"kuberule/backend/storage"
)

type Evaluator struct {
	DB            *sql.DB
	OwnerLabelKey string
}

func NewEvaluator(db *sql.DB) *Evaluator {
	ownerLabelKey := os.Getenv("OWNER_LABEL_KEY")
	if ownerLabelKey == "" {
		ownerLabelKey = "team"
	}

	return &Evaluator{
		DB:            db,
		OwnerLabelKey: ownerLabelKey,
	}
}

func (e *Evaluator) Evaluate(clusterID string) ([]map[string]interface{}, error) {
	guardrailPacksData, err := storage.FetchGuardrailPacks()
	if err != nil {
		return nil, err
	}

	clusterDerived, err := derived.BuildDerived(clusterID)
	if err != nil {
		return nil, err
	}

	namespaceLabelMap := make(map[string]map[string]string)
	for _, namespace := range clusterDerived.Namespaces {
		namespaceLabelMap[namespace.Name] = namespace.Labels
	}

	seenFindingKeys := []string{}
	seenFindingKeySet := make(map[string]bool)

	results := make([]map[string]interface{}, 0)

	for _, packData := range guardrailPacksData {
		raw, ok := packData["pack"]
		if !ok {
			continue
		}

		packJSON, err := json.Marshal(raw)
		if err != nil {
			continue
		}

		var guardrailPack models.GuardrailPack
		if err := json.Unmarshal(packJSON, &guardrailPack); err != nil {
			continue
		}

		if !packAppliesToCluster(guardrailPack, clusterID) {
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
					finding := e.createFinding(guardrailEntry, target, clusterID, evidence, namespaceLabelMap)

					targetIdentifier := finding["target_identifier"].(string)
					findingKey := guardrailEntry.ID + "|" + targetIdentifier

					if !seenFindingKeySet[findingKey] {
						seenFindingKeys = append(seenFindingKeys, findingKey)
						seenFindingKeySet[findingKey] = true
					}

					if err := storage.ReopenResolvedFinding(guardrailEntry.ID, targetIdentifier); err != nil {
						log.Printf("reopen finding %s/%s: %v", guardrailEntry.ID, targetIdentifier, err)
					}

					if err := storage.UpsertFinding(finding); err != nil {
						log.Printf("upsert finding %s/%s: %v", guardrailEntry.ID, targetIdentifier, err)
					}
				}
			}

			results = append(results, evaluationResult)
		}
	}

	resolvedCount, err := storage.AutoResolveFindings(clusterID, seenFindingKeys)
	if err != nil {
		log.Printf("auto-resolve findings: %v", err)
	} else if resolvedCount > 0 {
		log.Printf("Auto-resolved %d findings no longer present on cluster %s", resolvedCount, clusterID)
	}

	recordEvaluationSnapshot(clusterID)

	return results, nil
}

func recordEvaluationSnapshot(clusterID string) {
	bySeverity, err := storage.CountFindingsBySeverity(clusterID, "open")
	if err != nil {
		log.Printf("evaluation snapshot (severity counts): %v", err)
		return
	}

	byStatus, err := storage.CountFindingsByStatus(clusterID)
	if err != nil {
		log.Printf("evaluation snapshot (status counts): %v", err)
		return
	}

	critical := bySeverity["critical"]
	high := bySeverity["high"]
	medium := bySeverity["medium"]
	low := bySeverity["low"]

	openCount := byStatus["open"]
	acknowledgedCount := byStatus["acknowledged"]
	resolvedCount := byStatus["resolved"]
	totalCount := openCount + acknowledgedCount + resolvedCount

	healthScore := 100 - (critical*10 + high*5 + medium*1)
	if healthScore < 0 {
		healthScore = 0
	}

	compliancePct := 100.0
	if totalCount > 0 {
		compliancePct = float64(resolvedCount) / float64(totalCount) * 100.0
	}

	if err := storage.InsertEvaluationRun(clusterID, totalCount, openCount, resolvedCount, critical, high, medium, low, healthScore, compliancePct); err != nil {
		log.Printf("record evaluation run: %v", err)
	}
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
		log.Printf("Warning: unknown target type %s", guardrailEntry.Target)
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
	case "resource_limits":
		return e.checkResourceLimits(target, guardrailEntry.Check.Params)
	case "pod_security_policy":
		return e.checkPodSecurityPolicy(target, guardrailEntry.Check.Params)
	case "health_checks":
		return e.checkHealthChecks(target, guardrailEntry.Check.Params)
	default:
		log.Printf("Warning: unknown check type %s", guardrailEntry.Check.Type)
		return true, make(map[string]interface{})
	}
}

func pass() (bool, map[string]interface{}) {
	return true, map[string]interface{}{}
}

func (e *Evaluator) checkVulnThreshold(target interface{}, params map[string]interface{}) (bool, map[string]interface{}) {
	img, ok := target.(derived.ImageEnriched)
	if !ok {
		return pass()
	}

	maxCritical := intParam(params, "maxCritical", 0)
	if img.Vulnerabilities.Critical <= maxCritical {
		return pass()
	}

	return false, map[string]interface{}{
		"critical":     img.Vulnerabilities.Critical,
		"high":         img.Vulnerabilities.High,
		"medium":       img.Vulnerabilities.Medium,
		"low":          img.Vulnerabilities.Low,
		"max_critical": maxCritical,
	}
}

func (e *Evaluator) checkRequiredLabel(target interface{}, params map[string]interface{}) (bool, map[string]interface{}) {
	ns, ok := target.(derived.NamespaceEnriched)
	if !ok {
		return pass()
	}

	labelKey := stringParam(params, "labelKey", "")
	if labelKey == "" {
		return pass()
	}

	if _, ok := ns.Labels[labelKey]; ok {
		return pass()
	}

	return false, map[string]interface{}{
		"missing_label":  labelKey,
		"present_labels": ns.Labels,
	}
}

func (e *Evaluator) checkUnusedImages(target interface{}, params map[string]interface{}) (bool, map[string]interface{}) {
	node, ok := target.(derived.NodeEnriched)
	if !ok {
		return pass()
	}

	maxUnused := intParam(params, "maxUnused", 0)
	if len(node.UnusedImages) <= maxUnused {
		return pass()
	}

	return false, map[string]interface{}{
		"unused_count":  len(node.UnusedImages),
		"max_unused":    maxUnused,
		"unused_images": node.UnusedImages,
	}
}

func packAppliesToCluster(pack models.GuardrailPack, clusterID string) bool {
	if len(pack.Spec.Scope.Clusters) == 0 {
		return true
	}

	for _, allowedCluster := range pack.Spec.Scope.Clusters {
		if allowedCluster == "*" {
			return true
		}

		if allowedCluster == clusterID {
			return true
		}
	}

	return false
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
			} else if guardrail.Target == "pod" {
				pod, ok := target.(derived.PodEnriched)
				if !ok {
					continue
				}
				if pod.Namespace == exception.Value {
					return true
				}
			}
		}

		if exception.Type == "name" {
			if guardrail.Target == "node" {
				node, ok := target.(derived.NodeEnriched)
				if !ok {
					continue
				}
				if node.Name == exception.Value {
					return true
				}
			}
		}
	}
	return false
}

func (e *Evaluator) createFinding(guardrailEntry models.GuardrailEntry, target interface{}, clusterID string, evidence map[string]interface{}, namespaceLabelMap map[string]map[string]string) map[string]interface{} {
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
		log.Printf("Warning: unknown target type for finding")
		targetIdentifier = "unknown"
	}

	ownerLabelValue := ""
	if namespace != "" {
		labels, hasNamespace := namespaceLabelMap[namespace]
		if hasNamespace {
			value, hasLabel := labels[e.OwnerLabelKey]
			if hasLabel {
				ownerLabelValue = value
			}
		}
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
		"owner_label_value": ownerLabelValue,
	}

	return finding
}

func (e *Evaluator) checkResourceLimits(target interface{}, params map[string]interface{}) (bool, map[string]interface{}) {
	pod, ok := target.(derived.PodEnriched)
	if !ok {
		return pass()
	}

	requireLimits := boolParam(params, "requireLimits", true)
	requireRequests := boolParam(params, "requireRequests", true)

	hasResourceFields := func(resources map[string]interface{}, key string) bool {
		fields, ok := resources[key].(map[string]interface{})
		if !ok || fields == nil {
			return false
		}
		return fields["cpu"] != nil || fields["memory"] != nil
	}

	var missingLimits, missingRequests []string
	for _, c := range pod.Containers {
		if requireLimits && !hasResourceFields(c.Resources, "limits") {
			missingLimits = append(missingLimits, c.Name)
		}
		if requireRequests && !hasResourceFields(c.Resources, "requests") {
			missingRequests = append(missingRequests, c.Name)
		}
	}

	if len(missingLimits) == 0 && len(missingRequests) == 0 {
		return pass()
	}

	return false, map[string]interface{}{
		"missing_limits":   missingLimits,
		"missing_requests": missingRequests,
	}
}

func (e *Evaluator) checkPodSecurityPolicy(target interface{}, params map[string]interface{}) (bool, map[string]interface{}) {
	pod, ok := target.(derived.PodEnriched)
	if !ok {
		return pass()
	}

	allowPrivileged := boolParam(params, "allowPrivileged", true)
	runAsNonRoot := boolParam(params, "runAsNonRoot", false)

	var violations []string

	if runAsNonRoot {
		switch {
		case pod.SecurityContext == nil:
			violations = append(violations, "Pod security context not set")
		default:
			v, set := pod.SecurityContext["runAsNonRoot"].(bool)
			if !set {
				violations = append(violations, "Pod runAsNonRoot not set")
			} else if !v {
				violations = append(violations, "Pod not running as non-root")
			}
		}
	}

	for _, c := range pod.Containers {
		if c.SecurityContext == nil {
			continue
		}
		if !allowPrivileged {
			if priv, _ := c.SecurityContext["privileged"].(bool); priv {
				violations = append(violations, "Container "+c.Name+" running as privileged")
			}
		}
		if runAsNonRoot {
			if v, set := c.SecurityContext["runAsNonRoot"].(bool); set && !v {
				violations = append(violations, "Container "+c.Name+" not running as non-root")
			}
		}
	}

	if len(violations) == 0 {
		return pass()
	}
	return false, map[string]interface{}{"violations": violations}
}

func (e *Evaluator) checkHealthChecks(target interface{}, params map[string]interface{}) (bool, map[string]interface{}) {
	pod, ok := target.(derived.PodEnriched)
	if !ok {
		return pass()
	}

	requireLiveness := boolParam(params, "requireLiveness", false)
	requireReadiness := boolParam(params, "requireReadiness", false)

	var missingLiveness, missingReadiness []string
	for _, c := range pod.Containers {
		if requireLiveness && len(c.LivenessProbe) == 0 {
			missingLiveness = append(missingLiveness, c.Name)
		}
		if requireReadiness && len(c.ReadinessProbe) == 0 {
			missingReadiness = append(missingReadiness, c.Name)
		}
	}

	if len(missingLiveness) == 0 && len(missingReadiness) == 0 {
		return pass()
	}

	return false, map[string]interface{}{
		"missing_liveness":  missingLiveness,
		"missing_readiness": missingReadiness,
	}
}

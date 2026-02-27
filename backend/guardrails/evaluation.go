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
		log.Printf("Error fetching guardrail packs: %v\n", err)
		return nil, err
	}

	clusterDerived, err := derived.BuildDerived(clusterID)
	if err != nil {
		log.Printf("Error building derived data for cluster %s: %v\n", clusterID, err)
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

		if !packAppliesToCluster(guardrailPack, clusterID) {
			log.Printf("Skipping pack %s for cluster %s (scope mismatch)\n", guardrailPack.Metadata.Name, clusterID)
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

					reopenErr := storage.ReopenResolvedFinding(guardrailEntry.ID, targetIdentifier)
					if reopenErr != nil {
						log.Printf("Error reopening resolved finding: %v\n", reopenErr)
					}

					upsertErr := storage.UpsertFinding(finding)
					if upsertErr != nil {
						log.Printf("Error upserting finding: %v\n", upsertErr)
					}
				}
			}

			results = append(results, evaluationResult)
		}
	}

	resolvedCount, autoResolveErr := storage.AutoResolveFindings(clusterID, seenFindingKeys)
	if autoResolveErr != nil {
		log.Printf("Error auto-resolving findings: %v\n", autoResolveErr)
	} else if resolvedCount > 0 {
		log.Printf("Auto-resolved %d findings no longer present on cluster %s\n", resolvedCount, clusterID)
	}

	recordEvaluationSnapshot(clusterID)

	return results, nil
}

func recordEvaluationSnapshot(clusterID string) {
	bySeverity, err := storage.CountFindingsBySeverity(clusterID, "open")
	if err != nil {
		log.Printf("Error counting by severity for run snapshot: %v\n", err)
		return
	}

	byStatus, err := storage.CountFindingsByStatus(clusterID)
	if err != nil {
		log.Printf("Error counting by status for run snapshot: %v\n", err)
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

	insertErr := storage.InsertEvaluationRun(clusterID, totalCount, openCount, resolvedCount, critical, high, medium, low, healthScore, compliancePct)
	if insertErr != nil {
		log.Printf("Error recording evaluation run: %v\n", insertErr)
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
	case "resource_limits":
		return e.checkResourceLimits(target, guardrailEntry.Check.Params)
	case "pod_security_policy":
		return e.checkPodSecurityPolicy(target, guardrailEntry.Check.Params)
	case "health_checks":
		return e.checkHealthChecks(target, guardrailEntry.Check.Params)
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
		log.Printf("Warning: unknown target type for finding\n")
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
	podEnriched, ok := target.(derived.PodEnriched)
	if !ok {
		log.Printf("Warning: target is not PodEnriched type\n")
		return true, make(map[string]interface{})
	}

	requireLimits := true
	requireRequests := true

	if reqLimitsInterface, hasReqLimits := params["requireLimits"]; hasReqLimits {
		if reqLimitsBool, ok := reqLimitsInterface.(bool); ok {
			requireLimits = reqLimitsBool
		}
	}

	if reqRequestsInterface, hasReqRequests := params["requireRequests"]; hasReqRequests {
		if reqRequestsBool, ok := reqRequestsInterface.(bool); ok {
			requireRequests = reqRequestsBool
		}
	}

	missingLimits := []string{}
	missingRequests := []string{}

	for _, container := range podEnriched.Containers {
		if container.Resources == nil {
			if requireLimits {
				missingLimits = append(missingLimits, container.Name)
			}
			if requireRequests {
				missingRequests = append(missingRequests, container.Name)
			}
			continue
		}

		if requireLimits {
			limits, hasLimits := container.Resources["limits"].(map[string]interface{})
			if !hasLimits || limits == nil || (limits["cpu"] == nil && limits["memory"] == nil) {
				missingLimits = append(missingLimits, container.Name)
			}
		}

		if requireRequests {
			requests, hasRequests := container.Resources["requests"].(map[string]interface{})
			if !hasRequests || requests == nil || (requests["cpu"] == nil && requests["memory"] == nil) {
				missingRequests = append(missingRequests, container.Name)
			}
		}
	}

	if len(missingLimits) > 0 || len(missingRequests) > 0 {
		evidence := map[string]interface{}{
			"missing_limits":   missingLimits,
			"missing_requests": missingRequests,
		}
		return false, evidence
	}

	return true, make(map[string]interface{})
}

func (e *Evaluator) checkPodSecurityPolicy(target interface{}, params map[string]interface{}) (bool, map[string]interface{}) {
	podEnriched, ok := target.(derived.PodEnriched)
	if !ok {
		log.Printf("Warning: target is not PodEnriched type\n")
		return true, make(map[string]interface{})
	}

	allowPrivileged := true
	runAsNonRoot := false

	if allowPrivInterface, hasAllowPriv := params["allowPrivileged"]; hasAllowPriv {
		if allowPrivBool, ok := allowPrivInterface.(bool); ok {
			allowPrivileged = allowPrivBool
		}
	}

	if runAsNonRootInterface, hasRunAsNonRoot := params["runAsNonRoot"]; hasRunAsNonRoot {
		if runAsNonRootBool, ok := runAsNonRootInterface.(bool); ok {
			runAsNonRoot = runAsNonRootBool
		}
	}

	violations := []string{}

	if podEnriched.SecurityContext != nil {
		if runAsNonRoot {
			if runAsNonRootVal, hasRunAsNonRoot := podEnriched.SecurityContext["runAsNonRoot"].(bool); hasRunAsNonRoot {
				if !runAsNonRootVal {
					violations = append(violations, "Pod not running as non-root")
				}
			} else {
				violations = append(violations, "Pod runAsNonRoot not set")
			}
		}
	} else if runAsNonRoot {
		violations = append(violations, "Pod security context not set")
	}

	for _, container := range podEnriched.Containers {
		if container.SecurityContext != nil {
			if !allowPrivileged {
				if privileged, hasPrivileged := container.SecurityContext["privileged"].(bool); hasPrivileged && privileged {
					violations = append(violations, "Container "+container.Name+" running as privileged")
				}
			}

			if runAsNonRoot {
				if runAsNonRootVal, hasRunAsNonRoot := container.SecurityContext["runAsNonRoot"].(bool); hasRunAsNonRoot {
					if !runAsNonRootVal {
						violations = append(violations, "Container "+container.Name+" not running as non-root")
					}
				}
			}
		}
	}

	if len(violations) > 0 {
		evidence := map[string]interface{}{
			"violations": violations,
		}
		return false, evidence
	}

	return true, make(map[string]interface{})
}

func (e *Evaluator) checkHealthChecks(target interface{}, params map[string]interface{}) (bool, map[string]interface{}) {
	podEnriched, ok := target.(derived.PodEnriched)
	if !ok {
		log.Printf("Warning: target is not PodEnriched type\n")
		return true, make(map[string]interface{})
	}

	requireLiveness := false
	requireReadiness := false

	if reqLivenessInterface, hasReqLiveness := params["requireLiveness"]; hasReqLiveness {
		if reqLivenessBool, ok := reqLivenessInterface.(bool); ok {
			requireLiveness = reqLivenessBool
		}
	}

	if reqReadinessInterface, hasReqReadiness := params["requireReadiness"]; hasReqReadiness {
		if reqReadinessBool, ok := reqReadinessInterface.(bool); ok {
			requireReadiness = reqReadinessBool
		}
	}

	missingLiveness := []string{}
	missingReadiness := []string{}

	for _, container := range podEnriched.Containers {
		if requireLiveness && len(container.LivenessProbe) == 0 {
			missingLiveness = append(missingLiveness, container.Name)
		}

		if requireReadiness && len(container.ReadinessProbe) == 0 {
			missingReadiness = append(missingReadiness, container.Name)
		}
	}

	if len(missingLiveness) > 0 || len(missingReadiness) > 0 {
		evidence := map[string]interface{}{
			"missing_liveness":  missingLiveness,
			"missing_readiness": missingReadiness,
		}
		return false, evidence
	}

	return true, make(map[string]interface{})
}

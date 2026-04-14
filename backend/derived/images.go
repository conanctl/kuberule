package derived

import (
	"encoding/json"
	"log"

	"kuberule/backend/models"
)

func parseImages(payload string) []ImageEnriched {
	var scans []interface{}
	if err := json.Unmarshal([]byte(payload), &scans); err != nil {
		log.Printf("unmarshal image-scans payload: %v", err)
		return []ImageEnriched{}
	}

	byName := make(map[string]*ImageEnriched)

	for _, s := range scans {
		scan, ok := s.(map[string]interface{})
		if !ok {
			continue
		}
		name, ok := scan["ArtifactName"].(string)
		if !ok || name == "" {
			continue
		}

		var counts models.SeverityCounts
		if results, ok := scan["Results"].([]interface{}); ok {
			for _, r := range results {
				result, ok := r.(map[string]interface{})
				if !ok {
					continue
				}
				vulns, ok := result["Vulnerabilities"].([]interface{})
				if !ok {
					continue
				}
				counts.Add(countVulnerabilitiesBySeverity(vulns))
			}
		}

		if existing, ok := byName[name]; ok {
			existing.Vulnerabilities.Add(counts)
		} else {
			byName[name] = &ImageEnriched{
				Name:            name,
				Vulnerabilities: counts,
				UsedBy:          []string{},
				Nodes:           []string{},
				Status:          "active",
			}
		}
	}

	out := make([]ImageEnriched, 0, len(byName))
	for _, img := range byName {
		out = append(out, *img)
	}
	return out
}

func countVulnerabilitiesBySeverity(vulnerabilities []interface{}) models.SeverityCounts {
	var counts models.SeverityCounts
	for _, v := range vulnerabilities {
		vuln, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		severity, _ := vuln["Severity"].(string)
		switch severity {
		case "CRITICAL":
			counts.Critical++
		case "HIGH":
			counts.High++
		case "MEDIUM":
			counts.Medium++
		case "LOW":
			counts.Low++
		}
	}
	return counts
}

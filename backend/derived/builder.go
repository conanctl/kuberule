package derived

import (
	"log"

	"kuberule/backend/models"
	"kuberule/backend/storage"
)

func BuildDerived(clusterID string) (*ClusterDerived, error) {
	snapshots, err := storage.FetchSnapshots(clusterID, "trivy-scan")
	if err != nil {
		return nil, err
	}

	clusterDerived := &ClusterDerived{
		ClusterID:  clusterID,
		Images:     []ImageEnriched{},
		Workloads:  []WorkloadEnriched{},
		Nodes:      []NodeEnriched{},
		Namespaces: []NamespaceEnriched{},
	}

	if len(snapshots) == 0 {
		return clusterDerived, nil
	}

	latestSnapshot := snapshots[0]
	payloadData, ok := latestSnapshot["payload"].(map[string]interface{})
	if !ok {
		log.Printf("Could not cast payload to map for cluster %s\n", clusterID)
		return clusterDerived, nil
	}

	results, ok := payloadData["Results"].([]interface{})
	if !ok {
		log.Printf("Could not find Results in trivy scan for cluster %s\n", clusterID)
		return clusterDerived, nil
	}

	imageMap := make(map[string]*ImageEnriched)

	for _, resultInterface := range results {
		result, ok := resultInterface.(map[string]interface{})
		if !ok {
			continue
		}

		target, ok := result["Target"].(string)
		if !ok {
			continue
		}

		vulnerabilities, ok := result["Vulnerabilities"].([]interface{})
		if !ok {
			vulnerabilities = []interface{}{}
		}

		severityCounts := countVulnerabilitiesBySeverity(vulnerabilities)

		if imageEnriched, exists := imageMap[target]; exists {
			imageEnriched.Vulnerabilities.Critical += severityCounts.Critical
			imageEnriched.Vulnerabilities.High += severityCounts.High
			imageEnriched.Vulnerabilities.Medium += severityCounts.Medium
			imageEnriched.Vulnerabilities.Low += severityCounts.Low
		} else {
			emptySeverityCounts := models.SeverityCounts{
				Critical: severityCounts.Critical,
				High:     severityCounts.High,
				Medium:   severityCounts.Medium,
				Low:      severityCounts.Low,
			}
			newImageEnriched := &ImageEnriched{
				Name:            target,
				Vulnerabilities: emptySeverityCounts,
				UsedBy:          []string{},
				Nodes:           []string{},
				Status:          "active",
			}
			imageMap[target] = newImageEnriched
		}

		log.Printf("Processed trivy result for image %s with %d vulnerabilities\n", target, len(vulnerabilities))
	}

	for _, imageEnriched := range imageMap {
		clusterDerived.Images = append(clusterDerived.Images, *imageEnriched)
	}

	return clusterDerived, nil
}

func countVulnerabilitiesBySeverity(vulnerabilities []interface{}) models.SeverityCounts {
	severityCounts := models.SeverityCounts{
		Critical: 0,
		High:     0,
		Medium:   0,
		Low:      0,
	}

	for _, vulnInterface := range vulnerabilities {
		vuln, ok := vulnInterface.(map[string]interface{})
		if !ok {
			continue
		}

		severity, ok := vuln["Severity"].(string)
		if !ok {
			continue
		}

		switch severity {
		case "CRITICAL":
			severityCounts.Critical++
		case "HIGH":
			severityCounts.High++
		case "MEDIUM":
			severityCounts.Medium++
		case "LOW":
			severityCounts.Low++
		}
	}

	return severityCounts
}

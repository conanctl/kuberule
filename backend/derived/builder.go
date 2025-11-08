package derived

import (
	"encoding/json"
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
		Pods:       []PodEnriched{},
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

	workloadsSnapshots, err := storage.FetchSnapshots(clusterID, "workloads")
	if err != nil {
		log.Printf("Error fetching workloads for cluster %s: %v\n", clusterID, err)
	} else if len(workloadsSnapshots) > 0 {
		latestWorkloadsSnapshot := workloadsSnapshots[0]
		payloadValue, ok := latestWorkloadsSnapshot["payload"]
		if ok {
			switch v := payloadValue.(type) {
			case string:
				pods := parsePods(v)
				clusterDerived.Pods = pods
				log.Printf("Parsed %d pods from workloads snapshot\n", len(pods))
			case map[string]interface{}:
				payloadBytes, err := json.Marshal(v)
				if err == nil {
					pods := parsePods(string(payloadBytes))
					clusterDerived.Pods = pods
					log.Printf("Parsed %d pods from workloads snapshot\n", len(pods))
				}
			}
		}
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

func parsePods(workloadsPayload string) []PodEnriched {
	podsEnriched := []PodEnriched{}

	var payloadData map[string]interface{}
	err := json.Unmarshal([]byte(workloadsPayload), &payloadData)
	if err != nil {
		log.Printf("Error unmarshaling workloads payload: %v\n", err)
		return podsEnriched
	}

	podsInterface, ok := payloadData["pods"]
	if !ok {
		log.Println("No pods key found in workloads payload")
		return podsEnriched
	}

	podsList, ok := podsInterface.([]interface{})
	if !ok {
		log.Println("Could not cast pods to array")
		return podsEnriched
	}

	for _, podInterface := range podsList {
		pod, ok := podInterface.(map[string]interface{})
		if !ok {
			continue
		}

		podName, ok := pod["name"].(string)
		if !ok {
			continue
		}

		podNamespace, ok := pod["namespace"].(string)
		if !ok {
			podNamespace = "default"
		}

		podNodeName, ok := pod["nodeName"].(string)
		if !ok {
			podNodeName = ""
		}

		workloadName := ""
		workloadKind := ""

		ownerReferencesInterface, hasOwnerReferences := pod["ownerReferences"]
		if hasOwnerReferences {
			ownerReferences, ok := ownerReferencesInterface.([]interface{})
			if ok && len(ownerReferences) > 0 {
				ownerRef, ok := ownerReferences[0].(map[string]interface{})
				if ok {
					wName, ok := ownerRef["name"].(string)
					if ok {
						workloadName = wName
					}

					wKind, ok := ownerRef["kind"].(string)
					if ok {
						workloadKind = wKind
					}
				}
			}
		}

		images := []string{}

		specInterface, hasSpec := pod["spec"]
		if hasSpec {
			spec, ok := specInterface.(map[string]interface{})
			if ok {
				containersInterface, hasContainers := spec["containers"]
				if hasContainers {
					containers, ok := containersInterface.([]interface{})
					if ok {
						for _, containerInterface := range containers {
							container, ok := containerInterface.(map[string]interface{})
							if ok {
								imageString, ok := container["image"].(string)
								if ok {
									images = append(images, imageString)
								}
							}
						}
					}
				}
			}
		}

		podEnriched := PodEnriched{
			Name:         podName,
			Namespace:    podNamespace,
			NodeName:     podNodeName,
			WorkloadName: workloadName,
			WorkloadKind: workloadKind,
			Images:       images,
		}

		podsEnriched = append(podsEnriched, podEnriched)
	}

	return podsEnriched
}

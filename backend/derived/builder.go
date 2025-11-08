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
			var workloadsPayloadString string

			switch v := payloadValue.(type) {
			case string:
				workloadsPayloadString = v
			case map[string]interface{}:
				payloadBytes, err := json.Marshal(v)
				if err == nil {
					workloadsPayloadString = string(payloadBytes)
				}
			}

			if workloadsPayloadString != "" {
				pods := parsePods(workloadsPayloadString)
				clusterDerived.Pods = pods
				log.Printf("Parsed %d pods from workloads snapshot\n", len(pods))

				workloads := parseWorkloads(workloadsPayloadString, clusterDerived.Pods, clusterDerived.Images)
				clusterDerived.Workloads = workloads
				log.Printf("Parsed %d workloads from workloads snapshot\n", len(workloads))

				namespaces := parseNamespaces(workloadsPayloadString, clusterDerived.Workloads, clusterDerived.Images)
				clusterDerived.Namespaces = namespaces
				log.Printf("Parsed %d namespaces from workloads snapshot\n", len(namespaces))
			}
		}
	}

	nodesSnapshots, err := storage.FetchSnapshots(clusterID, "nodes")
	if err != nil {
		log.Printf("Error fetching nodes for cluster %s: %v\n", clusterID, err)
	} else if len(nodesSnapshots) > 0 {
		latestNodesSnapshot := nodesSnapshots[0]
		payloadValue, ok := latestNodesSnapshot["payload"]
		if ok {
			var nodesPayloadString string

			switch v := payloadValue.(type) {
			case string:
				nodesPayloadString = v
			case map[string]interface{}:
				payloadBytes, err := json.Marshal(v)
				if err == nil {
					nodesPayloadString = string(payloadBytes)
				}
			}

			if nodesPayloadString != "" {
				nodes := parseNodes(nodesPayloadString, clusterDerived.Pods, clusterDerived.Images)
				clusterDerived.Nodes = nodes
				log.Printf("Parsed %d nodes from nodes snapshot\n", len(nodes))
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

func parseWorkloads(workloadsPayload string, pods []PodEnriched, images []ImageEnriched) []WorkloadEnriched {
	workloadsEnriched := []WorkloadEnriched{}

	var payloadData map[string]interface{}
	err := json.Unmarshal([]byte(workloadsPayload), &payloadData)
	if err != nil {
		log.Printf("Error unmarshaling workloads payload: %v\n", err)
		return workloadsEnriched
	}

	imageMap := make(map[string]*ImageEnriched)
	for index := range images {
		imageMap[images[index].Name] = &images[index]
	}

	deploymentsInterface, hasDeployments := payloadData["deployments"]
	if hasDeployments {
		deployments, ok := deploymentsInterface.([]interface{})
		if ok {
			for _, deploymentInterface := range deployments {
				deployment, ok := deploymentInterface.(map[string]interface{})
				if !ok {
					continue
				}

				deploymentName, ok := deployment["name"].(string)
				if !ok {
					continue
				}

				deploymentNamespace, ok := deployment["namespace"].(string)
				if !ok {
					deploymentNamespace = "default"
				}

				workloadPodsCount := 0
				workloadImages := []string{}
				workloadImagesMap := make(map[string]bool)

				for _, pod := range pods {
					if pod.WorkloadName == deploymentName && pod.Namespace == deploymentNamespace {
						workloadPodsCount++

						for _, image := range pod.Images {
							if !workloadImagesMap[image] {
								workloadImages = append(workloadImages, image)
								workloadImagesMap[image] = true
							}
						}
					}
				}

				vulnerabilityCounts := models.SeverityCounts{
					Critical: 0,
					High:     0,
					Medium:   0,
					Low:      0,
				}

				for _, imageName := range workloadImages {
					if imageData, exists := imageMap[imageName]; exists {
						vulnerabilityCounts.Critical += imageData.Vulnerabilities.Critical
						vulnerabilityCounts.High += imageData.Vulnerabilities.High
						vulnerabilityCounts.Medium += imageData.Vulnerabilities.Medium
						vulnerabilityCounts.Low += imageData.Vulnerabilities.Low
					}
				}

				workloadEnriched := WorkloadEnriched{
					Name:            deploymentName,
					Kind:            "Deployment",
					Namespace:       deploymentNamespace,
					PodCount:        workloadPodsCount,
					Images:          workloadImages,
					Vulnerabilities: vulnerabilityCounts,
				}

				workloadsEnriched = append(workloadsEnriched, workloadEnriched)
			}
		}
	}

	statefulSetsInterface, hasStatefulSets := payloadData["statefulsets"]
	if hasStatefulSets {
		statefulSets, ok := statefulSetsInterface.([]interface{})
		if ok {
			for _, statefulSetInterface := range statefulSets {
				statefulSet, ok := statefulSetInterface.(map[string]interface{})
				if !ok {
					continue
				}

				statefulSetName, ok := statefulSet["name"].(string)
				if !ok {
					continue
				}

				statefulSetNamespace, ok := statefulSet["namespace"].(string)
				if !ok {
					statefulSetNamespace = "default"
				}

				workloadPodsCount := 0
				workloadImages := []string{}
				workloadImagesMap := make(map[string]bool)

				for _, pod := range pods {
					if pod.WorkloadName == statefulSetName && pod.Namespace == statefulSetNamespace {
						workloadPodsCount++

						for _, image := range pod.Images {
							if !workloadImagesMap[image] {
								workloadImages = append(workloadImages, image)
								workloadImagesMap[image] = true
							}
						}
					}
				}

				vulnerabilityCounts := models.SeverityCounts{
					Critical: 0,
					High:     0,
					Medium:   0,
					Low:      0,
				}

				for _, imageName := range workloadImages {
					if imageData, exists := imageMap[imageName]; exists {
						vulnerabilityCounts.Critical += imageData.Vulnerabilities.Critical
						vulnerabilityCounts.High += imageData.Vulnerabilities.High
						vulnerabilityCounts.Medium += imageData.Vulnerabilities.Medium
						vulnerabilityCounts.Low += imageData.Vulnerabilities.Low
					}
				}

				workloadEnriched := WorkloadEnriched{
					Name:            statefulSetName,
					Kind:            "StatefulSet",
					Namespace:       statefulSetNamespace,
					PodCount:        workloadPodsCount,
					Images:          workloadImages,
					Vulnerabilities: vulnerabilityCounts,
				}

				workloadsEnriched = append(workloadsEnriched, workloadEnriched)
			}
		}
	}

	daemonSetsInterface, hasDaemonSets := payloadData["daemonsets"]
	if hasDaemonSets {
		daemonSets, ok := daemonSetsInterface.([]interface{})
		if ok {
			for _, daemonSetInterface := range daemonSets {
				daemonSet, ok := daemonSetInterface.(map[string]interface{})
				if !ok {
					continue
				}

				daemonSetName, ok := daemonSet["name"].(string)
				if !ok {
					continue
				}

				daemonSetNamespace, ok := daemonSet["namespace"].(string)
				if !ok {
					daemonSetNamespace = "default"
				}

				workloadPodsCount := 0
				workloadImages := []string{}
				workloadImagesMap := make(map[string]bool)

				for _, pod := range pods {
					if pod.WorkloadName == daemonSetName && pod.Namespace == daemonSetNamespace {
						workloadPodsCount++

						for _, image := range pod.Images {
							if !workloadImagesMap[image] {
								workloadImages = append(workloadImages, image)
								workloadImagesMap[image] = true
							}
						}
					}
				}

				vulnerabilityCounts := models.SeverityCounts{
					Critical: 0,
					High:     0,
					Medium:   0,
					Low:      0,
				}

				for _, imageName := range workloadImages {
					if imageData, exists := imageMap[imageName]; exists {
						vulnerabilityCounts.Critical += imageData.Vulnerabilities.Critical
						vulnerabilityCounts.High += imageData.Vulnerabilities.High
						vulnerabilityCounts.Medium += imageData.Vulnerabilities.Medium
						vulnerabilityCounts.Low += imageData.Vulnerabilities.Low
					}
				}

				workloadEnriched := WorkloadEnriched{
					Name:            daemonSetName,
					Kind:            "DaemonSet",
					Namespace:       daemonSetNamespace,
					PodCount:        workloadPodsCount,
					Images:          workloadImages,
					Vulnerabilities: vulnerabilityCounts,
				}

				workloadsEnriched = append(workloadsEnriched, workloadEnriched)
			}
		}
	}

	return workloadsEnriched
}

func parseNodes(nodesPayload string, pods []PodEnriched, images []ImageEnriched) []NodeEnriched {
	nodesEnriched := []NodeEnriched{}

	var payloadData map[string]interface{}
	err := json.Unmarshal([]byte(nodesPayload), &payloadData)
	if err != nil {
		log.Printf("Error unmarshaling nodes payload: %v\n", err)
		return nodesEnriched
	}

	nodesInterface, ok := payloadData["nodes"]
	if !ok {
		log.Println("No nodes key found in nodes payload")
		return nodesEnriched
	}

	nodesList, ok := nodesInterface.([]interface{})
	if !ok {
		log.Println("Could not cast nodes to array")
		return nodesEnriched
	}

	imageMap := make(map[string]*ImageEnriched)
	for index := range images {
		imageMap[images[index].Name] = &images[index]
	}

	for _, nodeInterface := range nodesList {
		node, ok := nodeInterface.(map[string]interface{})
		if !ok {
			continue
		}

		nodeName, ok := node["name"].(string)
		if !ok {
			continue
		}

		usedImages := []string{}
		usedImagesMap := make(map[string]bool)
		allNodeImages := []string{}

		for _, pod := range pods {
			if pod.NodeName == nodeName {
				for _, image := range pod.Images {
					if !usedImagesMap[image] {
						usedImages = append(usedImages, image)
						usedImagesMap[image] = true
					}
				}
			}
		}

		nodeImagesInterface, hasNodeImages := node["images"]
		if hasNodeImages {
			nodeImagesList, ok := nodeImagesInterface.([]interface{})
			if ok {
				for _, imgInterface := range nodeImagesList {
					imgStr, ok := imgInterface.(string)
					if ok {
						allNodeImages = append(allNodeImages, imgStr)
					}
				}
			}
		}

		unusedImages := []string{}
		unusedImagesMap := make(map[string]bool)

		for _, nodeImage := range allNodeImages {
			if !usedImagesMap[nodeImage] && !unusedImagesMap[nodeImage] {
				unusedImages = append(unusedImages, nodeImage)
				unusedImagesMap[nodeImage] = true
			}
		}

		vulnerabilityCounts := models.SeverityCounts{
			Critical: 0,
			High:     0,
			Medium:   0,
			Low:      0,
		}

		for _, imageName := range usedImages {
			if imageData, exists := imageMap[imageName]; exists {
				vulnerabilityCounts.Critical += imageData.Vulnerabilities.Critical
				vulnerabilityCounts.High += imageData.Vulnerabilities.High
				vulnerabilityCounts.Medium += imageData.Vulnerabilities.Medium
				vulnerabilityCounts.Low += imageData.Vulnerabilities.Low
			}
		}

		nodeEnriched := NodeEnriched{
			Name:            nodeName,
			UsedImages:      usedImages,
			UnusedImages:    unusedImages,
			Vulnerabilities: vulnerabilityCounts,
		}

		nodesEnriched = append(nodesEnriched, nodeEnriched)
	}

	return nodesEnriched
}

func parseNamespaces(workloadsPayload string, workloads []WorkloadEnriched, images []ImageEnriched) []NamespaceEnriched {
	namespacesEnriched := []NamespaceEnriched{}

	var payloadData map[string]interface{}
	err := json.Unmarshal([]byte(workloadsPayload), &payloadData)
	if err != nil {
		log.Printf("Error unmarshaling workloads payload for namespaces: %v\n", err)
		return namespacesEnriched
	}

	namespaceWorkloadsMap := make(map[string]int)
	namespaceImagesMap := make(map[string]map[string]bool)

	for _, workload := range workloads {
		namespaceWorkloadsMap[workload.Namespace]++

		if _, exists := namespaceImagesMap[workload.Namespace]; !exists {
			namespaceImagesMap[workload.Namespace] = make(map[string]bool)
		}

		for _, image := range workload.Images {
			namespaceImagesMap[workload.Namespace][image] = true
		}
	}

	namespacesInterface, hasNamespaces := payloadData["namespaces"]
	if hasNamespaces {
		namespacesList, ok := namespacesInterface.([]interface{})
		if ok {
			for _, namespaceInterface := range namespacesList {
				namespace, ok := namespaceInterface.(map[string]interface{})
				if !ok {
					continue
				}

				namespaceName, ok := namespace["name"].(string)
				if !ok {
					continue
				}

				labelsInterface, hasLabels := namespace["labels"]
				namespaceLabels := make(map[string]string)
				if hasLabels {
					labels, ok := labelsInterface.(map[string]interface{})
					if ok {
						for key, value := range labels {
							valueStr, ok := value.(string)
							if ok {
								namespaceLabels[key] = valueStr
							}
						}
					}
				}

				workloadCount := namespaceWorkloadsMap[namespaceName]
				imageCount := len(namespaceImagesMap[namespaceName])

				imageMap := make(map[string]*ImageEnriched)
				for index := range images {
					imageMap[images[index].Name] = &images[index]
				}

				vulnerabilityCounts := models.SeverityCounts{
					Critical: 0,
					High:     0,
					Medium:   0,
					Low:      0,
				}

				for imageName := range namespaceImagesMap[namespaceName] {
					if imageData, exists := imageMap[imageName]; exists {
						vulnerabilityCounts.Critical += imageData.Vulnerabilities.Critical
						vulnerabilityCounts.High += imageData.Vulnerabilities.High
						vulnerabilityCounts.Medium += imageData.Vulnerabilities.Medium
						vulnerabilityCounts.Low += imageData.Vulnerabilities.Low
					}
				}

				namespaceEnriched := NamespaceEnriched{
					Name:            namespaceName,
					WorkloadCount:   workloadCount,
					ImageCount:      imageCount,
					Vulnerabilities: vulnerabilityCounts,
					Labels:          namespaceLabels,
				}

				namespacesEnriched = append(namespacesEnriched, namespaceEnriched)
			}
		}
	}

	return namespacesEnriched
}

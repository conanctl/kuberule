package derived

import (
	"encoding/json"
	"log"

	"kuberule/backend/models"
	"kuberule/backend/storage"
)

func BuildDerived(clusterID string) (*ClusterDerived, error) {
	clusterDerived := &ClusterDerived{
		ClusterID:  clusterID,
		Images:     []ImageEnriched{},
		Workloads:  []WorkloadEnriched{},
		Nodes:      []NodeEnriched{},
		Namespaces: []NamespaceEnriched{},
		Pods:       []PodEnriched{},
	}

	imageScansSnapshots, err := storage.FetchSnapshots(clusterID, "image-scans")
	if err != nil {
		log.Printf("Error fetching image-scans for cluster %s: %v\n", clusterID, err)
	} else if len(imageScansSnapshots) > 0 {
		latestSnapshot := imageScansSnapshots[0]
		payloadString := extractPayloadString(latestSnapshot)
		if payloadString != "" {
			images := parseImages(payloadString)
			clusterDerived.Images = images
			log.Printf("Parsed %d images from image-scans snapshot\n", len(images))
		}
	}

	workloadsSnapshots, err := storage.FetchSnapshots(clusterID, "workloads")
	if err != nil {
		log.Printf("Error fetching workloads for cluster %s: %v\n", clusterID, err)
	} else if len(workloadsSnapshots) > 0 {
		latestSnapshot := workloadsSnapshots[0]
		payloadString := extractPayloadString(latestSnapshot)
		if payloadString != "" {
			pods := parsePods(payloadString)
			clusterDerived.Pods = pods
			log.Printf("Parsed %d pods from workloads snapshot\n", len(pods))

			workloads := parseWorkloads(payloadString, clusterDerived.Pods, clusterDerived.Images)
			clusterDerived.Workloads = workloads
			log.Printf("Parsed %d workloads from workloads snapshot\n", len(workloads))
		}
	}

	nodesSnapshots, err := storage.FetchSnapshots(clusterID, "nodes")
	if err != nil {
		log.Printf("Error fetching nodes for cluster %s: %v\n", clusterID, err)
	} else if len(nodesSnapshots) > 0 {
		latestSnapshot := nodesSnapshots[0]
		payloadString := extractPayloadString(latestSnapshot)
		if payloadString != "" {
			nodes := parseNodes(payloadString, clusterDerived.Pods, clusterDerived.Images)
			clusterDerived.Nodes = nodes
			log.Printf("Parsed %d nodes from nodes snapshot\n", len(nodes))
		}
	}

	namespacesSnapshots, err := storage.FetchSnapshots(clusterID, "namespaces")
	if err != nil {
		log.Printf("Error fetching namespaces for cluster %s: %v\n", clusterID, err)
	} else if len(namespacesSnapshots) > 0 {
		latestSnapshot := namespacesSnapshots[0]
		payloadString := extractPayloadString(latestSnapshot)
		if payloadString != "" {
			namespaces := parseNamespaces(payloadString, clusterDerived.Workloads, clusterDerived.Images)
			clusterDerived.Namespaces = namespaces
			log.Printf("Parsed %d namespaces from namespaces snapshot\n", len(namespaces))
		}
	}

	return clusterDerived, nil
}

func extractPayloadString(snapshot map[string]interface{}) string {
	payloadValue, ok := snapshot["payload"]
	if !ok {
		return ""
	}

	payloadMap, isMap := payloadValue.(map[string]interface{})
	if isMap {
		nestedPayload, hasNested := payloadMap["payload"]
		if hasNested {
			payloadBytes, err := json.Marshal(nestedPayload)
			if err == nil {
				return string(payloadBytes)
			}
		}

		payloadBytes, err := json.Marshal(payloadMap)
		if err == nil {
			return string(payloadBytes)
		}
	}

	payloadStr, isStr := payloadValue.(string)
	if isStr {
		return payloadStr
	}

	return ""
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

func parseImages(imageScansPayload string) []ImageEnriched {
	imagesEnriched := []ImageEnriched{}

	var imageScansList []interface{}
	err := json.Unmarshal([]byte(imageScansPayload), &imageScansList)
	if err != nil {
		log.Printf("Error unmarshaling image-scans payload: %v\n", err)
		return imagesEnriched
	}

	imageMap := make(map[string]*ImageEnriched)

	for _, scanInterface := range imageScansList {
		scan, ok := scanInterface.(map[string]interface{})
		if !ok {
			continue
		}

		imageName, ok := scan["ArtifactName"].(string)
		if !ok {
			continue
		}

		if imageName == "" {
			continue
		}

		severityCounts := models.SeverityCounts{
			Critical: 0,
			High:     0,
			Medium:   0,
			Low:      0,
		}

		resultsInterface, hasResults := scan["Results"]
		if hasResults {
			resultsList, ok := resultsInterface.([]interface{})
			if ok {
				for _, resultInterface := range resultsList {
					result, ok := resultInterface.(map[string]interface{})
					if !ok {
						continue
					}

					vulnerabilitiesInterface, hasVulns := result["Vulnerabilities"]
					if !hasVulns {
						continue
					}

					vulnerabilities, ok := vulnerabilitiesInterface.([]interface{})
					if !ok {
						continue
					}

					counts := countVulnerabilitiesBySeverity(vulnerabilities)
					severityCounts.Critical += counts.Critical
					severityCounts.High += counts.High
					severityCounts.Medium += counts.Medium
					severityCounts.Low += counts.Low
				}
			}
		}

		existing, found := imageMap[imageName]
		if found {
			existing.Vulnerabilities.Critical += severityCounts.Critical
			existing.Vulnerabilities.High += severityCounts.High
			existing.Vulnerabilities.Medium += severityCounts.Medium
			existing.Vulnerabilities.Low += severityCounts.Low
		} else {
			imageMap[imageName] = &ImageEnriched{
				Name:            imageName,
				Vulnerabilities: severityCounts,
				UsedBy:          []string{},
				Nodes:           []string{},
				Status:          "active",
			}
		}
	}

	for _, imageEnriched := range imageMap {
		imagesEnriched = append(imagesEnriched, *imageEnriched)
	}

	return imagesEnriched
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

	var podsList []interface{}

	if podsMap, ok := podsInterface.(map[string]interface{}); ok {
		if items, hasItems := podsMap["items"].([]interface{}); hasItems {
			podsList = items
		}
	} else if directList, ok := podsInterface.([]interface{}); ok {
		podsList = directList
	}

	if len(podsList) == 0 {
		log.Println("No pods found in payload")
		return podsEnriched
	}

	for _, podInterface := range podsList {
		pod, ok := podInterface.(map[string]interface{})
		if !ok {
			continue
		}

		metadata, hasMetadata := pod["metadata"].(map[string]interface{})
		if !hasMetadata {
			continue
		}

		podName, ok := metadata["name"].(string)
		if !ok {
			continue
		}

		podNamespace, ok := metadata["namespace"].(string)
		if !ok {
			podNamespace = "default"
		}

		spec, hasSpec := pod["spec"].(map[string]interface{})
		if !hasSpec {
			continue
		}

		podNodeName, _ := spec["nodeName"].(string)

		workloadName := ""
		workloadKind := ""

		ownerReferencesInterface, hasOwnerReferences := metadata["ownerReferences"]
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
		containers := []ContainerEnriched{}
		var podSecurityContext map[string]interface{}

		if secCtx, hasSecCtx := spec["securityContext"].(map[string]interface{}); hasSecCtx {
			podSecurityContext = secCtx
		}

		containersInterface, hasContainers := spec["containers"]
		if hasContainers {
			containersList, ok := containersInterface.([]interface{})
			if ok {
				for _, containerInterface := range containersList {
					container, ok := containerInterface.(map[string]interface{})
					if ok {
						imageString, _ := container["image"].(string)
						images = append(images, imageString)

						containerName, _ := container["name"].(string)
						resources, _ := container["resources"].(map[string]interface{})
						containerSecCtx, _ := container["securityContext"].(map[string]interface{})
						livenessProbe, _ := container["livenessProbe"].(map[string]interface{})
						readinessProbe, _ := container["readinessProbe"].(map[string]interface{})

						containerEnriched := ContainerEnriched{
							Name:            containerName,
							Image:           imageString,
							Resources:       resources,
							SecurityContext: containerSecCtx,
							LivenessProbe:   livenessProbe,
							ReadinessProbe:  readinessProbe,
						}
						containers = append(containers, containerEnriched)
					}
				}
			}
		}

		podEnriched := PodEnriched{
			Name:            podName,
			Namespace:       podNamespace,
			NodeName:        podNodeName,
			WorkloadName:    workloadName,
			WorkloadKind:    workloadKind,
			Images:          images,
			SecurityContext: podSecurityContext,
			Containers:      containers,
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

	workloadKindsToRead := []struct {
		payloadKey string
		kindLabel  string
	}{
		{"deployments", "Deployment"},
		{"statefulsets", "StatefulSet"},
		{"daemonsets", "DaemonSet"},
		{"replicasets", "ReplicaSet"},
	}

	for _, kindEntry := range workloadKindsToRead {
		workloadsInterface, hasWorkloads := payloadData[kindEntry.payloadKey]
		if !hasWorkloads {
			continue
		}

		var workloadItems []interface{}

		if workloadsMap, ok := workloadsInterface.(map[string]interface{}); ok {
			if items, hasItems := workloadsMap["items"].([]interface{}); hasItems {
				workloadItems = items
			}
		} else if directList, ok := workloadsInterface.([]interface{}); ok {
			workloadItems = directList
		}

		for _, workloadInterface := range workloadItems {
			workload, ok := workloadInterface.(map[string]interface{})
			if !ok {
				continue
			}

			metadata, hasMetadata := workload["metadata"].(map[string]interface{})
			if !hasMetadata {
				continue
			}

			workloadName, ok := metadata["name"].(string)
			if !ok {
				continue
			}

			workloadNamespace, ok := metadata["namespace"].(string)
			if !ok {
				workloadNamespace = "default"
			}

			workloadPodsCount := 0
			workloadImages := []string{}
			workloadImagesMap := make(map[string]bool)

			for _, pod := range pods {
				if pod.WorkloadName == workloadName && pod.Namespace == workloadNamespace {
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
				Name:            workloadName,
				Kind:            kindEntry.kindLabel,
				Namespace:       workloadNamespace,
				PodCount:        workloadPodsCount,
				Images:          workloadImages,
				Vulnerabilities: vulnerabilityCounts,
			}

			workloadsEnriched = append(workloadsEnriched, workloadEnriched)
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

	itemsInterface, ok := payloadData["items"]
	if !ok {
		log.Println("No items key found in nodes payload")
		return nodesEnriched
	}

	nodesList, ok := itemsInterface.([]interface{})
	if !ok {
		log.Println("Could not cast items to array")
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

		metadata, hasMetadata := node["metadata"].(map[string]interface{})
		if !hasMetadata {
			continue
		}

		nodeName, ok := metadata["name"].(string)
		if !ok {
			continue
		}

		usedImages := []string{}
		usedImagesMap := make(map[string]bool)

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

		allNodeImages := []string{}

		status, hasStatus := node["status"].(map[string]interface{})
		if hasStatus {
			statusImagesInterface, hasImages := status["images"]
			if hasImages {
				statusImagesList, ok := statusImagesInterface.([]interface{})
				if ok {
					for _, imgEntryInterface := range statusImagesList {
						imgEntry, ok := imgEntryInterface.(map[string]interface{})
						if !ok {
							continue
						}

						namesInterface, hasNames := imgEntry["names"]
						if !hasNames {
							continue
						}

						namesList, ok := namesInterface.([]interface{})
						if !ok {
							continue
						}

						for _, nameInterface := range namesList {
							name, ok := nameInterface.(string)
							if ok {
								allNodeImages = append(allNodeImages, name)
							}
						}
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

func parseNamespaces(namespacesPayload string, workloads []WorkloadEnriched, images []ImageEnriched) []NamespaceEnriched {
	namespacesEnriched := []NamespaceEnriched{}

	var payloadData map[string]interface{}
	err := json.Unmarshal([]byte(namespacesPayload), &payloadData)
	if err != nil {
		log.Printf("Error unmarshaling namespaces payload: %v\n", err)
		return namespacesEnriched
	}

	itemsInterface, ok := payloadData["items"]
	if !ok {
		log.Println("No items key found in namespaces payload")
		return namespacesEnriched
	}

	namespacesList, ok := itemsInterface.([]interface{})
	if !ok {
		log.Println("Could not cast items to array")
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

	imageMap := make(map[string]*ImageEnriched)
	for index := range images {
		imageMap[images[index].Name] = &images[index]
	}

	for _, namespaceInterface := range namespacesList {
		namespace, ok := namespaceInterface.(map[string]interface{})
		if !ok {
			continue
		}

		metadata, hasMetadata := namespace["metadata"].(map[string]interface{})
		if !hasMetadata {
			continue
		}

		namespaceName, ok := metadata["name"].(string)
		if !ok {
			continue
		}

		namespaceLabels := make(map[string]string)
		labelsInterface, hasLabels := metadata["labels"]
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

	return namespacesEnriched
}

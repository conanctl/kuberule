package derived

import (
	"encoding/json"
	"log"

	"kuberule/backend/models"
)

var workloadKinds = []struct {
	payloadKey string
	kindLabel  string
}{
	{"deployments", "Deployment"},
	{"statefulsets", "StatefulSet"},
	{"daemonsets", "DaemonSet"},
	{"replicasets", "ReplicaSet"},
}

func parseWorkloads(payload string, pods []PodEnriched, images []ImageEnriched) []WorkloadEnriched {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		log.Printf("unmarshal workloads payload: %v", err)
		return []WorkloadEnriched{}
	}

	imageIdx := indexImagesByName(images)
	out := []WorkloadEnriched{}

	for _, k := range workloadKinds {
		for _, item := range extractItems(data, k.payloadKey) {
			w, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if enriched, ok := workloadFromRaw(w, k.kindLabel, pods, imageIdx); ok {
				out = append(out, enriched)
			}
		}
	}

	return out
}

func workloadFromRaw(workload map[string]interface{}, kind string, pods []PodEnriched, imageIdx map[string]*ImageEnriched) (WorkloadEnriched, bool) {
	metadata, ok := workload["metadata"].(map[string]interface{})
	if !ok {
		return WorkloadEnriched{}, false
	}
	name, ok := metadata["name"].(string)
	if !ok {
		return WorkloadEnriched{}, false
	}
	namespace, _ := metadata["namespace"].(string)
	if namespace == "" {
		namespace = "default"
	}

	podCount := 0
	seenImages := map[string]bool{}
	images := []string{}

	for _, pod := range pods {
		if pod.WorkloadName == name && pod.Namespace == namespace {
			podCount++
			for _, image := range pod.Images {
				if !seenImages[image] {
					images = append(images, image)
					seenImages[image] = true
				}
			}
		}
	}

	var vulns models.SeverityCounts
	for _, imageName := range images {
		if img, ok := imageIdx[imageName]; ok {
			vulns.Add(img.Vulnerabilities)
		}
	}

	return WorkloadEnriched{
		Name:            name,
		Kind:            kind,
		Namespace:       namespace,
		PodCount:        podCount,
		Images:          images,
		Vulnerabilities: vulns,
	}, true
}

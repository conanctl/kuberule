package derived

import (
	"encoding/json"
	"log"

	"kuberule/backend/models"
)

func parseNamespaces(payload string, workloads []WorkloadEnriched, images []ImageEnriched) []NamespaceEnriched {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		log.Printf("unmarshal namespaces payload: %v", err)
		return []NamespaceEnriched{}
	}

	items, ok := data["items"].([]interface{})
	if !ok {
		return []NamespaceEnriched{}
	}

	workloadCount, imageSetsByNS := rollupWorkloadsByNamespace(workloads)
	imageIdx := indexImagesByName(images)
	out := make([]NamespaceEnriched, 0, len(items))

	for _, n := range items {
		namespace, ok := n.(map[string]interface{})
		if !ok {
			continue
		}
		if enriched, ok := namespaceFromRaw(namespace, workloadCount, imageSetsByNS, imageIdx); ok {
			out = append(out, enriched)
		}
	}

	return out
}

func rollupWorkloadsByNamespace(workloads []WorkloadEnriched) (map[string]int, map[string]map[string]bool) {
	counts := map[string]int{}
	imagesByNS := map[string]map[string]bool{}

	for _, w := range workloads {
		counts[w.Namespace]++
		if _, ok := imagesByNS[w.Namespace]; !ok {
			imagesByNS[w.Namespace] = map[string]bool{}
		}
		for _, image := range w.Images {
			imagesByNS[w.Namespace][image] = true
		}
	}
	return counts, imagesByNS
}

func namespaceFromRaw(ns map[string]interface{}, workloadCount map[string]int, imageSetsByNS map[string]map[string]bool, imageIdx map[string]*ImageEnriched) (NamespaceEnriched, bool) {
	metadata, ok := ns["metadata"].(map[string]interface{})
	if !ok {
		return NamespaceEnriched{}, false
	}
	name, ok := metadata["name"].(string)
	if !ok {
		return NamespaceEnriched{}, false
	}

	labels := map[string]string{}
	if raw, ok := metadata["labels"].(map[string]interface{}); ok {
		for k, v := range raw {
			if s, ok := v.(string); ok {
				labels[k] = s
			}
		}
	}

	var vulns models.SeverityCounts
	for imageName := range imageSetsByNS[name] {
		if img, ok := imageIdx[imageName]; ok {
			vulns.Add(img.Vulnerabilities)
		}
	}

	return NamespaceEnriched{
		Name:            name,
		WorkloadCount:   workloadCount[name],
		ImageCount:      len(imageSetsByNS[name]),
		Vulnerabilities: vulns,
		Labels:          labels,
	}, true
}

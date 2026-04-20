package derived

import (
	"encoding/json"
	"log"

	"kuberule/backend/models"
)

func parseNodes(payload string, pods []PodEnriched, images []ImageEnriched) []NodeEnriched {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		log.Printf("unmarshal nodes payload: %v", err)
		return []NodeEnriched{}
	}

	items := extractItems(data, "items")
	if items == nil {
		if arr, ok := data["items"].([]interface{}); ok {
			items = arr
		}
	}
	if len(items) == 0 {
		return []NodeEnriched{}
	}

	imageIdx := indexImagesByName(images)
	out := make([]NodeEnriched, 0, len(items))

	for _, n := range items {
		node, ok := n.(map[string]interface{})
		if !ok {
			continue
		}
		if enriched, ok := nodeFromRaw(node, pods, imageIdx); ok {
			out = append(out, enriched)
		}
	}
	return out
}

func nodeFromRaw(node map[string]interface{}, pods []PodEnriched, imageIdx map[string]*ImageEnriched) (NodeEnriched, bool) {
	metadata, ok := node["metadata"].(map[string]interface{})
	if !ok {
		return NodeEnriched{}, false
	}
	name, ok := metadata["name"].(string)
	if !ok {
		return NodeEnriched{}, false
	}

	usedImages, usedSet := imagesUsedOnNode(name, pods)
	unused := unusedNodeImages(node, usedSet)

	var vulns models.SeverityCounts
	for _, imageName := range usedImages {
		if img, ok := imageIdx[imageName]; ok {
			vulns.Add(img.Vulnerabilities)
		}
	}

	return NodeEnriched{
		Name:            name,
		UsedImages:      usedImages,
		UnusedImages:    unused,
		Vulnerabilities: vulns,
	}, true
}

func imagesUsedOnNode(nodeName string, pods []PodEnriched) ([]string, map[string]bool) {
	seen := map[string]bool{}
	used := []string{}
	for _, pod := range pods {
		if pod.NodeName != nodeName {
			continue
		}
		for _, image := range pod.Images {
			if !seen[image] {
				used = append(used, image)
				seen[image] = true
			}
		}
	}
	return used, seen
}

func unusedNodeImages(node map[string]interface{}, usedSet map[string]bool) []string {
	status, ok := node["status"].(map[string]interface{})
	if !ok {
		return []string{}
	}
	entries, ok := status["images"].([]interface{})
	if !ok {
		return []string{}
	}

	unused := []string{}
	seen := map[string]bool{}

	for _, e := range entries {
		entry, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		names, ok := entry["names"].([]interface{})
		if !ok {
			continue
		}
		for _, n := range names {
			name, ok := n.(string)
			if !ok {
				continue
			}
			if !usedSet[name] && !seen[name] {
				unused = append(unused, name)
				seen[name] = true
			}
		}
	}
	return unused
}

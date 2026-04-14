package derived

import (
	"encoding/json"
	"log"

	"kuberule/backend/storage"
)

// BuildDerived pulls the latest raw snapshots for a cluster and turns them
// into the enriched model the UI and evaluator consume. Order matters: images
// feed workload/node/namespace vulnerability rollups, and pods feed workload
// and node membership counts.
func BuildDerived(clusterID string) (*ClusterDerived, error) {
	out := &ClusterDerived{
		ClusterID:  clusterID,
		Images:     []ImageEnriched{},
		Workloads:  []WorkloadEnriched{},
		Nodes:      []NodeEnriched{},
		Namespaces: []NamespaceEnriched{},
		Pods:       []PodEnriched{},
	}

	if payload := latestSnapshotPayload(clusterID, "image-scans"); payload != "" {
		out.Images = parseImages(payload)
		log.Printf("parsed %d images from image-scans snapshot", len(out.Images))
	}

	if payload := latestSnapshotPayload(clusterID, "workloads"); payload != "" {
		out.Pods = parsePods(payload)
		out.Workloads = parseWorkloads(payload, out.Pods, out.Images)
		log.Printf("parsed %d pods and %d workloads from workloads snapshot", len(out.Pods), len(out.Workloads))
	}

	if payload := latestSnapshotPayload(clusterID, "nodes"); payload != "" {
		out.Nodes = parseNodes(payload, out.Pods, out.Images)
		log.Printf("parsed %d nodes from nodes snapshot", len(out.Nodes))
	}

	if payload := latestSnapshotPayload(clusterID, "namespaces"); payload != "" {
		out.Namespaces = parseNamespaces(payload, out.Workloads, out.Images)
		log.Printf("parsed %d namespaces from namespaces snapshot", len(out.Namespaces))
	}

	return out, nil
}

func latestSnapshotPayload(clusterID, kind string) string {
	snapshots, err := storage.FetchSnapshots(clusterID, kind)
	if err != nil {
		log.Printf("fetching %s for cluster %q: %v", kind, clusterID, err)
		return ""
	}
	if len(snapshots) == 0 {
		return ""
	}
	return extractPayloadString(snapshots[0])
}

// Snapshots are stored as the full ingest envelope ({cluster_id, kind, payload}),
// so the content we actually want to parse is always the inner "payload" field.
// We re-marshal it to JSON because the downstream parsers all work with strings.
func extractPayloadString(snapshot map[string]interface{}) string {
	envelope, ok := snapshot["payload"].(map[string]interface{})
	if !ok {
		return ""
	}
	inner, ok := envelope["payload"]
	if !ok {
		return ""
	}
	bytes, err := json.Marshal(inner)
	if err != nil {
		return ""
	}
	return string(bytes)
}

func indexImagesByName(images []ImageEnriched) map[string]*ImageEnriched {
	idx := make(map[string]*ImageEnriched, len(images))
	for i := range images {
		idx[images[i].Name] = &images[i]
	}
	return idx
}

func extractItems(payloadData map[string]interface{}, key string) []interface{} {
	raw, ok := payloadData[key]
	if !ok {
		return nil
	}
	if asMap, ok := raw.(map[string]interface{}); ok {
		if items, ok := asMap["items"].([]interface{}); ok {
			return items
		}
		return nil
	}
	if direct, ok := raw.([]interface{}); ok {
		return direct
	}
	return nil
}

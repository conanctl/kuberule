package derived

import (
	"encoding/json"
	"log"
)

func parsePods(payload string) []PodEnriched {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		log.Printf("unmarshal workloads payload: %v", err)
		return []PodEnriched{}
	}

	items := extractItems(data, "pods")
	if len(items) == 0 {
		return []PodEnriched{}
	}

	out := make([]PodEnriched, 0, len(items))
	for _, p := range items {
		pod, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		if enriched, ok := podFromRaw(pod); ok {
			out = append(out, enriched)
		}
	}
	return out
}

func podFromRaw(pod map[string]interface{}) (PodEnriched, bool) {
	metadata, ok := pod["metadata"].(map[string]interface{})
	if !ok {
		return PodEnriched{}, false
	}
	name, ok := metadata["name"].(string)
	if !ok {
		return PodEnriched{}, false
	}
	namespace, _ := metadata["namespace"].(string)
	if namespace == "" {
		namespace = "default"
	}
	spec, ok := pod["spec"].(map[string]interface{})
	if !ok {
		return PodEnriched{}, false
	}
	nodeName, _ := spec["nodeName"].(string)

	workloadName, workloadKind := ownerRef(metadata)

	podSecCtx, _ := spec["securityContext"].(map[string]interface{})
	images, containers := containersFromSpec(spec)

	return PodEnriched{
		Name:            name,
		Namespace:       namespace,
		NodeName:        nodeName,
		WorkloadName:    workloadName,
		WorkloadKind:    workloadKind,
		Images:          images,
		SecurityContext: podSecCtx,
		Containers:      containers,
	}, true
}

func ownerRef(metadata map[string]interface{}) (name, kind string) {
	refs, ok := metadata["ownerReferences"].([]interface{})
	if !ok || len(refs) == 0 {
		return "", ""
	}
	first, ok := refs[0].(map[string]interface{})
	if !ok {
		return "", ""
	}
	name, _ = first["name"].(string)
	kind, _ = first["kind"].(string)
	return name, kind
}

func containersFromSpec(spec map[string]interface{}) ([]string, []ContainerEnriched) {
	raw, ok := spec["containers"].([]interface{})
	if !ok {
		return []string{}, nil
	}

	images := make([]string, 0, len(raw))
	containers := make([]ContainerEnriched, 0, len(raw))

	for _, c := range raw {
		container, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		image, _ := container["image"].(string)
		images = append(images, image)

		name, _ := container["name"].(string)
		resources, _ := container["resources"].(map[string]interface{})
		secCtx, _ := container["securityContext"].(map[string]interface{})
		liveness, _ := container["livenessProbe"].(map[string]interface{})
		readiness, _ := container["readinessProbe"].(map[string]interface{})

		containers = append(containers, ContainerEnriched{
			Name:            name,
			Image:           image,
			Resources:       resources,
			SecurityContext: secCtx,
			LivenessProbe:   liveness,
			ReadinessProbe:  readiness,
		})
	}

	return images, containers
}

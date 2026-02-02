package derived

import "kuberule/backend/models"

type ClusterDerived struct {
	ClusterID  string              `json:"cluster_id"`
	Images     []ImageEnriched     `json:"images"`
	Workloads  []WorkloadEnriched  `json:"workloads"`
	Nodes      []NodeEnriched      `json:"nodes"`
	Namespaces []NamespaceEnriched `json:"namespaces"`
	Pods       []PodEnriched       `json:"pods"`
}

type ImageEnriched struct {
	Name            string                `json:"name"`
	Vulnerabilities models.SeverityCounts `json:"vulnerabilities"`
	UsedBy          []string              `json:"used_by"`
	Nodes           []string              `json:"nodes"`
	Status          string                `json:"status"`
}

type WorkloadEnriched struct {
	Name            string                `json:"name"`
	Kind            string                `json:"kind"`
	Namespace       string                `json:"namespace"`
	PodCount        int                   `json:"pod_count"`
	Images          []string              `json:"images"`
	Vulnerabilities models.SeverityCounts `json:"vulnerabilities"`
}

type NodeEnriched struct {
	Name            string                `json:"name"`
	UsedImages      []string              `json:"used_images"`
	UnusedImages    []string              `json:"unused_images"`
	Vulnerabilities models.SeverityCounts `json:"vulnerabilities"`
}

type NamespaceEnriched struct {
	Name            string                `json:"name"`
	WorkloadCount   int                   `json:"workload_count"`
	ImageCount      int                   `json:"image_count"`
	Vulnerabilities models.SeverityCounts `json:"vulnerabilities"`
	Labels          map[string]string     `json:"labels"`
}

type PodEnriched struct {
	Name            string                 `json:"name"`
	Namespace       string                 `json:"namespace"`
	NodeName        string                 `json:"node_name"`
	WorkloadName    string                 `json:"workload_name"`
	WorkloadKind    string                 `json:"workload_kind"`
	Images          []string               `json:"images"`
	SecurityContext map[string]interface{} `json:"security_context"`
	Containers      []ContainerEnriched    `json:"containers"`
}

type ContainerEnriched struct {
	Name            string                 `json:"name"`
	Image           string                 `json:"image"`
	Resources       map[string]interface{} `json:"resources"`
	SecurityContext map[string]interface{} `json:"security_context"`
	LivenessProbe   map[string]interface{} `json:"liveness_probe"`
	ReadinessProbe  map[string]interface{} `json:"readiness_probe"`
}

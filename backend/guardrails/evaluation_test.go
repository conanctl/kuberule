package guardrails

import (
	"testing"

	"kuberule/backend/derived"
	"kuberule/backend/models"
)

func TestCheckVulnThreshold(t *testing.T) {
	cases := []struct {
		name       string
		image      derived.ImageEnriched
		params     map[string]interface{}
		wantPassed bool
	}{
		{
			name:       "under threshold passes",
			image:      derived.ImageEnriched{Vulnerabilities: models.SeverityCounts{Critical: 0}},
			params:     map[string]interface{}{"maxCritical": float64(0)},
			wantPassed: true,
		},
		{
			name:       "at threshold passes",
			image:      derived.ImageEnriched{Vulnerabilities: models.SeverityCounts{Critical: 3}},
			params:     map[string]interface{}{"maxCritical": float64(3)},
			wantPassed: true,
		},
		{
			name:       "over threshold fails",
			image:      derived.ImageEnriched{Vulnerabilities: models.SeverityCounts{Critical: 5}},
			params:     map[string]interface{}{"maxCritical": float64(2)},
			wantPassed: false,
		},
		{
			name:       "missing param falls back to 0",
			image:      derived.ImageEnriched{Vulnerabilities: models.SeverityCounts{Critical: 1}},
			params:     map[string]interface{}{},
			wantPassed: false,
		},
	}

	e := &Evaluator{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			passed, _ := e.checkVulnThreshold(tc.image, tc.params)
			if passed != tc.wantPassed {
				t.Errorf("got passed=%v, want %v", passed, tc.wantPassed)
			}
		})
	}
}

func TestCheckRequiredLabel(t *testing.T) {
	e := &Evaluator{}

	passed, _ := e.checkRequiredLabel(
		derived.NamespaceEnriched{Labels: map[string]string{"team": "platform"}},
		map[string]interface{}{"labelKey": "team"},
	)
	if !passed {
		t.Error("namespace with required label should pass")
	}

	passed, evidence := e.checkRequiredLabel(
		derived.NamespaceEnriched{Name: "orphan", Labels: map[string]string{"env": "prod"}},
		map[string]interface{}{"labelKey": "team"},
	)
	if passed {
		t.Error("namespace without required label should fail")
	}
	if evidence["missing_label"] != "team" {
		t.Errorf("evidence missing_label = %v, want team", evidence["missing_label"])
	}
}

func TestCheckResourceLimits(t *testing.T) {
	e := &Evaluator{}
	params := map[string]interface{}{"requireLimits": true, "requireRequests": true}

	// no resources, should fail
	pod := derived.PodEnriched{Containers: []derived.ContainerEnriched{
		{Name: "app"},
		{Name: "sidecar"},
	}}
	passed, evidence := e.checkResourceLimits(pod, params)
	if passed {
		t.Fatal("pod with no resources should fail")
	}
	missingLimits, _ := evidence["missing_limits"].([]string)
	if len(missingLimits) != 2 {
		t.Errorf("missing_limits len = %d, want 2", len(missingLimits))
	}

	// limits + requests set, should pass
	podOK := derived.PodEnriched{Containers: []derived.ContainerEnriched{
		{
			Name: "app",
			Resources: map[string]interface{}{
				"limits":   map[string]interface{}{"cpu": "500m"},
				"requests": map[string]interface{}{"memory": "256Mi"},
			},
		},
	}}
	if passed, _ := e.checkResourceLimits(podOK, params); !passed {
		t.Error("pod with limits and requests should pass")
	}
}

func TestPackAppliesToCluster(t *testing.T) {
	wildcard := models.GuardrailPack{Spec: models.GuardrailSpec{Scope: models.GuardrailScope{Clusters: []string{"*"}}}}
	scoped := models.GuardrailPack{Spec: models.GuardrailSpec{Scope: models.GuardrailScope{Clusters: []string{"prod", "staging"}}}}
	empty := models.GuardrailPack{}

	if !packAppliesToCluster(wildcard, "anything") {
		t.Error("wildcard should match any cluster")
	}
	if !packAppliesToCluster(empty, "anything") {
		t.Error("empty scope should match any cluster")
	}
	if !packAppliesToCluster(scoped, "prod") {
		t.Error("prod should match")
	}
	if packAppliesToCluster(scoped, "dev") {
		t.Error("dev should not match")
	}
}

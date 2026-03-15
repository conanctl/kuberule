package guardrails

// Check params arrive as map[string]interface{} because they're decoded from
// JSON alongside the rest of the pack. These helpers keep the per-check
// functions focused on the actual policy logic instead of on type assertions.

func intParam(params map[string]interface{}, key string, fallback int) int {
	v, ok := params[key]
	if !ok {
		return fallback
	}
	// JSON numbers always decode as float64.
	if n, ok := v.(float64); ok {
		return int(n)
	}
	return fallback
}

func stringParam(params map[string]interface{}, key, fallback string) string {
	v, ok := params[key].(string)
	if !ok {
		return fallback
	}
	return v
}

func boolParam(params map[string]interface{}, key string, fallback bool) bool {
	v, ok := params[key].(bool)
	if !ok {
		return fallback
	}
	return v
}

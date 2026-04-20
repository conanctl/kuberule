package guardrails

func intParam(params map[string]interface{}, key string, fallback int) int {
	v, ok := params[key]
	if !ok {
		return fallback
	}
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

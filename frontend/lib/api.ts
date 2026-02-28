const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:18081"

export async function getClusters(): Promise<{ clusters: string[] }> {
  const response = await fetch(`${API_BASE}/clusters`)
  if (!response.ok) {
    throw new Error("Failed to fetch clusters")
  }
  return response.json()
}

export async function getFindings(filters?: Record<string, string>) {
  let url = `${API_BASE}/findings`
  if (filters) {
    const params = new URLSearchParams(filters)
    const paramsString = params.toString()
    if (paramsString.length > 0) {
      url += `?${paramsString}`
    }
  }
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error("Failed to fetch findings")
  }
  const data = await response.json()
  if (data === null) {
    return []
  }
  return data
}

export async function updateFindingStatus(findingId: number, status: string) {
  const response = await fetch(`${API_BASE}/findings`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ finding_id: findingId, status }),
  })
  if (!response.ok) {
    throw new Error("Failed to update finding")
  }
  return response.json()
}

export async function getGuardrails() {
  const response = await fetch(`${API_BASE}/guardrails`)
  if (!response.ok) {
    throw new Error("Failed to fetch guardrails")
  }
  const data = await response.json()
  if (data === null) {
    return []
  }
  return data
}

export async function reloadGuardrails() {
  const response = await fetch(`${API_BASE}/guardrails/reload`, {
    method: "POST",
  })
  if (!response.ok) {
    throw new Error("Failed to reload guardrails")
  }
  return response.json()
}

export async function evaluateGuardrails(clusterId: string) {
  const response = await fetch(`${API_BASE}/guardrails/evaluate?cluster_id=${encodeURIComponent(clusterId)}`)
  if (!response.ok) {
    throw new Error("Failed to evaluate guardrails")
  }
  return response.json()
}

export async function getDerived(clusterId: string) {
  const response = await fetch(`${API_BASE}/cluster/state?cluster_id=${encodeURIComponent(clusterId)}`)
  if (!response.ok) {
    throw new Error("Failed to fetch derived data")
  }
  return response.json()
}

export async function getMetrics(clusterId: string) {
  let url = `${API_BASE}/metrics`
  if (clusterId !== "") {
    url += `?cluster_id=${encodeURIComponent(clusterId)}`
  }
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error("Failed to fetch metrics")
  }
  return response.json()
}

export async function getMetricsHistory(clusterId: string, limit = 50) {
  const params = new URLSearchParams()
  params.set("cluster_id", clusterId)
  params.set("limit", String(limit))
  const response = await fetch(`${API_BASE}/metrics/history?${params.toString()}`)
  if (!response.ok) {
    throw new Error("Failed to fetch metrics history")
  }
  return response.json()
}

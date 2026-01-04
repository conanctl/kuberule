import { mockFindings, mockGuardrails } from "./mock-data"

const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:18081"

export async function getClusters() {
  try {
    const response = await fetch(`${API_BASE}/clusters`)
    if (!response.ok) {
      throw new Error("Failed to fetch clusters")
    }
    return response.json()
  } catch {
    return { clusters: ["cluster-1", "cluster-2"] }
  }
}

export async function getFindings(filters?: Record<string, string>) {
  try {
    let url = `${API_BASE}/findings`
    if (filters) {
      const params = new URLSearchParams(filters)
      url += `?${params.toString()}`
    }
    const response = await fetch(url)
    if (!response.ok) {
      throw new Error("Failed to fetch findings")
    }
    return response.json()
  } catch {
    return mockFindings
  }
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
  try {
    const response = await fetch(`${API_BASE}/guardrails`)
    if (!response.ok) {
      throw new Error("Failed to fetch guardrails")
    }
    return response.json()
  } catch {
    return mockGuardrails
  }
}

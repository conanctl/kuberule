export interface SeverityCounts {
  critical: number
  high: number
  medium: number
  low: number
}

export interface Finding {
  id: number
  guardrail_id: string
  title: string
  category: string
  severity: string
  target_type: string
  target_identifier: string
  cluster_id: string
  namespace: string
  status: string
  first_seen_at: string
  last_seen_at: string
  evidence: Record<string, any>
  remediation_hint: string
  owner_label_value: string
}

export interface GuardrailPack {
  id: number
  name: string
  version: string
  loaded_at: string
  pack: {
    metadata: {
      name: string
      version: string
    }
    spec: {
      description: string
      owner: string
      guardrails: GuardrailEntry[]
    }
  }
}

export interface GuardrailEntry {
  id: string
  title: string
  category: string
  severity: string
  target: string
  check: {
    type: string
    params: Record<string, any>
  }
  remediationHint: string
  rationale: string
}

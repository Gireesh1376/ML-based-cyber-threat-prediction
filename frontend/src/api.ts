export type TierCounts = {
  critical?: number | null
  review?: number | null
  auto_log?: number | null
}

export type PerTierRow = {
  count?: number | null
  precision?: number | null
  false_positive_rate?: number | null
  benign_proportion?: number | null
  alerts_per_1000_flows?: number | null
  alerts_per_1000_benign_flows?: number | null
}

export type Problem3Summary = {
  workload?: {
    human_review_workload?: number | null
    auto_logged_share?: number | null
    tier_counts?: TierCounts
  }
  threat_preservation?: {
    attacks_in_human_tiers?: number | null
    attacks_outside_human_tiers?: number | null
    attacks_auto_logged?: number | null
    zero_days_in_human_tiers?: number | null
    zero_days_outside_human_tiers?: number | null
  }
  per_tier?: {
    critical?: PerTierRow
    review?: PerTierRow
    auto_log?: PerTierRow
  }
  auto_log_safety?: {
    auto_log?: {
      count?: number | null
      share_of_all_flows?: number | null
      attacks_in_auto_log?: number | null
      attacks_share_of_all_attacks?: number | null
      zero_days_in_auto_log?: number | null
      zero_days_share_of_all_zero_days?: number | null
    }
    human_tiers?: {
      count?: number | null
      share_of_all_flows?: number | null
      attacks_in_human_tiers?: number | null
      zero_days_in_human_tiers?: number | null
    }
    interpretation?: string
  }
  cutoffs_derived_on?: string
  limitation?: string
}

export type BinaryMetrics = {
  accuracy?: number
  precision?: number
  recall?: number
  f1?: number
  roc_auc?: number
  confusion_matrix?: number[][]
}

export type Summary = {
  ready: boolean
  message?: string
  problem?: string
  architecture?: string
  dataset?: string
  kpis?: Record<string, number | null>
  alert_mix?: Record<string, number>
  severity_mix?: Record<string, number>
  tier_mix?: Record<string, number>
  prioritisation?: {
    weights?: Record<string, number>
    tier_cutoffs?: Record<string, number>
    cutoffs_derived_on?: string
    test_evaluation?: Record<string, unknown>
  }
  problem3?: Problem3Summary
  held_out_labels?: string[]
  classes?: string[]
  train_rows?: number
  test_rows?: number
  validation_rows?: number
  unseen_zero_day_rows?: number
  validation_binary?: BinaryMetrics
  official_test_binary?: BinaryMetrics
  detection_comparison?: Record<string, any>
  zero_day?: Record<string, any>
  reconstruction_threshold?: number
}

type Tier = 'critical' | 'review' | 'auto_log'

export type AlertItem = {
  id: string
  src: string
  dst: string
  protocol: string
  service: string
  true_label: string
  predicted: string
  known_label: string
  confidence: number
  reconstruction_error: number
  is_zero_day: boolean
  severity: string
  priority: number
  tier: Tier
  priority_components: Record<string, number>
  asset_criticality: number
  asset_criticality_known: boolean
  tier_reason: string
  tier_floor_applied: boolean
  dq_flags: string[]
  flow?: Record<string, string | number>
}

export type AlertsResponse = {
  items: AlertItem[]
  count: number
  tier_cutoffs: Record<string, number>
}

export async function getAlerts(params?: { tier?: string; sort?: string; limit?: number }): Promise<AlertsResponse> {
  const qs = new URLSearchParams()
  if (params?.tier) qs.set('tier', params.tier)
  if (params?.sort) qs.set('sort', params.sort)
  if (params?.limit) qs.set('limit', String(params.limit))
  const res = await fetch(`${API}/api/alerts${qs.size ? `?${qs}` : ''}`)
  if (!res.ok) throw new Error('Failed to load alerts')
  return res.json()
}
export type DetectResult = {
  predicted: string
  known_class: string
  is_zero_day: boolean
  confidence: number
  reconstruction_error: number
  threshold: number
  anomaly_ratio: number
  priority: number
  priority_components: Record<string, number>
  tier: Tier
  asset_criticality: number
  asset_criticality_known: boolean
  tier_reason: string
  severity: string
  rationale: string
  explanation_kind?: 'shap' | 'feature_importance_fallback'
  top_features: { feature: string; impact: number; value: number }[]
  anomaly_features?: { feature: string; error_share: number; value: number; reconstructed: number }[]
  explanation_scope?: string
}

const API = ''

export async function getSummary(): Promise<Summary> {
  const res = await fetch(`${API}/api/dashboard/summary`)
  if (!res.ok) throw new Error('Failed to load dashboard')
  return res.json()
}

export async function getMetrics(): Promise<Record<string, unknown>> {
  const res = await fetch(`${API}/api/model/metrics`)
  if (!res.ok) throw new Error('Failed to load metrics')
  return res.json()
}

export async function getSchema(): Promise<{ features: string[]; presets: Record<string, Record<string, string | number>> }> {
  const res = await fetch(`${API}/api/detect/schema`)
  if (!res.ok) throw new Error('Failed to load schema')
  return res.json()
}

export async function detectFlow(payload: Record<string, string | number>): Promise<DetectResult> {
  const res = await fetch(`${API}/api/detect`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || 'Detection failed')
  }
  return res.json()
}

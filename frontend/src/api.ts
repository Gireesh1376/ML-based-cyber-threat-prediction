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
  adversarial?: {
    summary?: {
      method?: string
      description?: string
      epsilon?: number
      baseline_evasion_rate?: number
      hardened_evasion_rate?: number
      baseline_clf_evasion?: number
      hardened_clf_evasion?: number
      evasion_reduction_pct?: number
      hardened_attack_recall?: number
      adaptive_hardened_evasion_rate?: number
      adaptive_hardened_clf_evasion?: number
    }
    clean_metrics?: {
      baseline_attack_recall?: number
      hardened_attack_recall?: number
      baseline_fpr?: number
      hardened_fpr?: number
      fpr_penalty?: number
    }
  }
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
  source?: 'elasticsearch' | 'local_fallback' | string
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

export type FeatureDelta = {
  feature: string
  original: number | string
  perturbed: number | string
  delta: number | string
  invariant?: string
}

export type FlowPrediction = {
  predicted: string
  known_class: string
  confidence: number
  reconstruction_error: number
  anomaly_ratio: number
  is_zero_day: boolean
  priority: number
  tier: Tier
}

export type AdversarialSimulateResult = {
  method: string
  epsilon: number
  adaptive?: boolean
  sample_id?: string
  ground_truth_label?: string
  ground_truth_family?: string
  deltas_count: number
  feature_deltas: FeatureDelta[]
  perturbed_flow: Record<string, string | number>
  baseline_clean: FlowPrediction
  baseline_under_attack: FlowPrediction
  hardened_under_attack: FlowPrediction
  analysis: {
    baseline_evaded: boolean
    hardened_evaded: boolean
    evasion_blocked: boolean
    status: string
  }
}

export type QuadrantType =
  | 'hardened_caught_baseline_evaded'
  | 'both_caught'
  | 'both_failed'
  | 'baseline_caught_hardened_evaded'

export type AdversarialEvidenceCase = {
  case_id: string
  sample_index: number
  quadrant: QuadrantType
  ground_truth_label: string
  ground_truth_family: string
  method: string
  epsilon: number
  service: string
  protocol: string
  original_flow: Record<string, string | number>
  perturbed_flow: Record<string, string | number>
  deltas_count: number
  feature_deltas: FeatureDelta[]
  constraints_valid: boolean
  baseline: FlowPrediction & { evaded: boolean }
  hardened: FlowPrediction & { evaded: boolean }
  status: string
  notes: string
}

export type AdversarialEvidenceSummary = {
  total_samples: number
  baseline_evaded_count: number
  baseline_evasion_rate_pct: number
  hardened_evaded_count: number
  hardened_evasion_rate_pct: number
  percentage_point_difference: number
  relative_reduction_pct: number
  quadrant_counts: Record<QuadrantType, number>
  quadrant_percentages: Record<QuadrantType, number>
  quadrant_descriptions: Record<QuadrantType, string>
  investigation_notes: string
  demgan_limitation_notice: string
  benchmark_simulation_notice: string
}

export type AdversarialEvidenceResponse = {
  method: string
  epsilon: number
  summary: AdversarialEvidenceSummary
  quadrant_cases: Record<QuadrantType, AdversarialEvidenceCase[]>
}

export type AdversarialSweepItem = {
  method: string
  epsilon: number
  baseline_classifier_evasion: number
  hardened_classifier_evasion: number
  baseline_hybrid_evasion: number
  hardened_hybrid_evasion: number
  baseline_attack_recall: number
  hardened_attack_recall: number
  evasion_mitigation_pct: number
  adaptive_hardened_classifier_evasion?: number
  adaptive_hardened_hybrid_evasion?: number
  adaptive_hardened_attack_recall?: number
  valid_samples_count?: number
  total_samples_count?: number
  constraint_validity_pct?: number
}

export type AdversarialMetrics = {
  status: string
  clean_metrics: {
    baseline_attack_recall: number
    hardened_attack_recall: number
    baseline_fpr: number
    hardened_fpr: number
    fpr_penalty: number
  }
  adversarial_summary: {
    method: string
    epsilon: number
    baseline_evasion_rate: number
    hardened_evasion_rate: number
    baseline_clf_evasion: number
    hardened_clf_evasion: number
    evasion_reduction_pct: number
    hardened_attack_recall: number
  }
  sweep: AdversarialSweepItem[]
  domain_constraints: {
    rate_columns_clamped: number
    counts_non_negative: number
    immutable_columns_preserved: string[]
    invariants_enforced: string[]
  }
}

export type AdversarialPresetsResponse = {
  presets: Record<string, Record<string, string | number>>
  methods: Record<string, { name: string; description: string; type: string }>
}

export async function getAdversarialMetrics(): Promise<AdversarialMetrics> {
  const res = await fetch(`${API}/api/adversarial/metrics`)
  if (!res.ok) throw new Error('Failed to load adversarial metrics')
  return res.json()
}

export async function getAdversarialEvidence(
  method = 'fgsm',
  epsilon = 0.20,
): Promise<AdversarialEvidenceResponse> {
  const qs = new URLSearchParams({ method, epsilon: String(epsilon) })
  const res = await fetch(`${API}/api/adversarial/evidence?${qs}`)
  if (!res.ok) throw new Error('Failed to load adversarial evidence')
  return res.json()
}

export async function getAdversarialPresets(): Promise<AdversarialPresetsResponse> {
  const res = await fetch(`${API}/api/adversarial/presets`)
  if (!res.ok) throw new Error('Failed to load adversarial presets')
  return res.json()
}

export async function simulateAdversarial(payload: {
  preset?: string
  sample_id?: string
  flow?: Record<string, string | number>
  method?: string
  epsilon?: number
  adaptive?: boolean
}): Promise<AdversarialSimulateResult> {
  const res = await fetch(`${API}/api/adversarial/simulate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || 'Adversarial simulation failed')
  }
  return res.json()
}


export type DbStatus = {
  connected: boolean
  version?: string
  cluster_name?: string
  url?: string
  index?: string
  index_exists?: boolean
  docs_count?: number
  error?: string
}

export async function getDbStatus(): Promise<DbStatus> {
  const res = await fetch(`${API}/api/db/status`)
  if (!res.ok) throw new Error('Failed to load database status')
  return res.json()
}

export type HealthStatus = {
  status: string
  service: string
  database: {
    type: string
    connected: boolean
  }
}

export async function getHealth(): Promise<HealthStatus> {
  const res = await fetch(`${API}/api/health`)
  if (!res.ok) throw new Error('Health check failed')
  return res.json()
}

// ---------------------------------------------------------------------------
// Problem 2: Encrypted Traffic Analysis API
// ---------------------------------------------------------------------------

export type EncryptedPreset = {
  title: string
  category: string
  description: string
  flow: Record<string, any>
}

export type EncryptedSchemaResponse = {
  status: string
  model_architecture: string
  feature_count: number
  feature_names: string[]
  raw_inputs: {
    flow_transport: string[]
    splt_sequence: string[]
    protocol_fingerprints: string[]
  }
  presets: Record<string, EncryptedPreset>
  disclaimer: string
}

export type EncryptedMetricsResponse = {
  status?: string
  problem?: string
  dataset?: string
  model_architecture?: string
  split_summary?: {
    train_samples?: number
    test_samples?: number
    cutoff_date?: number
    train_unique_sample_ids?: number
    test_unique_sample_ids?: number
    sample_id_overlap?: number
    train_positive_ratio?: number
    test_positive_ratio?: number
  }
  ablation_comparison?: Record<string, {
    description?: string
    features?: number
    accuracy?: number
    recall?: number
    precision?: number
    fpr?: number
    roc_auc?: number
    f1?: number
  }>
  primary_evaluation?: {
    accuracy: number
    precision: number
    recall: number
    f1: number
    benign_fpr: number
    roc_auc: number
    pr_auc: number
    confusion_matrix: number[][]
  }
  slice_evaluation?: {
    seen_attack_families?: {
      sample_count?: number
      recall?: number
      detected_count?: number
    }
    zero_day_holdout_families?: {
      sample_count?: number
      family_count?: number
      recall?: number
      detected_count?: number
      families?: string[]
    }
    clean_runs_baseline?: {
      sample_count?: number
      fpr?: number
      false_positives?: number
    }
    family_breakdown?: Record<string, {
      total?: number
      detected?: number
      recall?: number
    }>
  }
  threshold_sweep?: Array<{
    threshold: number
    precision: number
    recall: number
    fpr: number
    f1: number
  }>
}

export type EncryptedDetectionResult = {
  id?: string
  predicted: string
  is_malicious: boolean
  confidence: number
  malicious_probability: number
  benign_probability: number
  decision_threshold: number
  priority: number
  tier: Tier
  tier_reason: string
  tier_floor_applied: boolean
  blocking_recommended: boolean
  mitigation_action: string
  priority_components: Record<string, number>
  asset_criticality: number
  top_features: Array<{
    feature: string
    importance: number
    direction: string
  }>
  dq_flags: string[]
  metadata_inspected: Record<string, any>
  payload_decrypted: boolean
  saved_to_db?: boolean
  db_status?: string
}

export type EncryptedLiveStatusResponse = {
  connected: boolean
  status: string
  mode: string
  live_pcap_supported: boolean
  active_interface?: string | null
  message: string
}

export async function getEncryptedSchema(): Promise<EncryptedSchemaResponse> {
  const res = await fetch(`${API}/api/encrypted/schema`)
  if (!res.ok) throw new Error('Failed to load encrypted traffic schema')
  return res.json()
}

export async function getEncryptedMetrics(): Promise<EncryptedMetricsResponse> {
  const res = await fetch(`${API}/api/encrypted/metrics`)
  if (!res.ok) throw new Error('Failed to load encrypted traffic benchmark metrics')
  return res.json()
}

export async function getEncryptedLiveStatus(): Promise<EncryptedLiveStatusResponse> {
  const res = await fetch(`${API}/api/encrypted/live-status`)
  if (!res.ok) throw new Error('Failed to load live status')
  return res.json()
}

export async function detectEncryptedFlow(flow: Record<string, any>): Promise<EncryptedDetectionResult> {
  const res = await fetch(`${API}/api/encrypted/detect`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(flow),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || 'Encrypted flow analysis failed')
  }
  return res.json()
}



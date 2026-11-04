import { useEffect, useState } from 'react'
import {
  Radar,
  Lock,
  BellRing,
  ShieldAlert,
  ArrowRight,
  Database,
  Workflow,
  ShieldCheck,
  Bot,
  LayoutDashboard,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Shield,
  ChevronRight,
  ChevronDown,
  Info,
  Sliders,
  Scale,
  GitFork,
  Boxes,
  Milestone,
  X,
  ExternalLink,
  Network,
  GitBranch,
  ArrowUpRight,
  Filter,
  Check
} from 'lucide-react'
import { Link } from 'react-router-dom'
import { getSummary, type Summary } from '../api'

type ViewSection = 'roadmap' | 'dependencies' | 'ecosystem' | 'governance'

interface DependencyWorkstream {
  id: string
  code: string
  name: string
  milestone: 'M1' | 'M2' | 'M3' | 'M4'
  milestoneTitle: string
  category: 'Security & Auth' | 'Persistence' | 'Reliability' | 'ML Governance' | 'Testing & QA' | 'Infrastructure'
  status: 'Ready / Foundation' | 'In Progress' | 'Dependent' | 'Planned'
  badgeClass: string
  tasks: { id: string; name: string; priority: string; cvss?: string }[]
  prerequisites: string[] // IDs of prerequisite workstreams
  unblocks: string[] // IDs of workstreams unblocked
  description: string
  risk: string
  acceptanceCriteria: string[]
}

export default function Roadmap() {
  const [summary, setSummary] = useState<Summary | null>(null)
  const [activeSection, setActiveSection] = useState<ViewSection>('roadmap')
  const [selectedStageIndex, setSelectedStageIndex] = useState<number>(1) // Default to Stage 2 (Current Baseline)
  const [selectedProblemId, setSelectedProblemId] = useState<string | null>(null)
  const [selectedModuleLetter, setSelectedModuleLetter] = useState<string | null>(null)
  const [selectedWorkstreamId, setSelectedWorkstreamId] = useState<string | null>('WS-SEC-AUTH')
  const [activeGovTab, setActiveGovTab] = useState<'principles' | 'gan_protocol' | 'matrix'>('principles')
  const [dependencyFilter, setDependencyFilter] = useState<'all' | 'M1' | 'M2' | 'M3' | 'M4'>('all')
  const [expandStageContent, setExpandStageContent] = useState<boolean>(false)

  useEffect(() => {
    getSummary().then(setSummary).catch(() => setSummary(null))
  }, [])

  // ---------------------------------------------------------------------------
  // 1. Foundational Research Problems (P1 – P4)
  // Preserves 100% of technical baseline, metrics & architectural limitations
  // ---------------------------------------------------------------------------
  const foundationalProblems = [
    {
      id: 'P1',
      title: 'Zero-Day / Unknown Attack Detection',
      shortTitle: 'Zero-Day Detection',
      tagline: 'Dual-tier anomaly gating via bottleneck reconstruction error & tree classification',
      subtitle: 'MLPRegressor Bottleneck Reconstruction Network + XGBoost Hybrid Detector',
      status: 'Validated Baseline',
      badgeClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
      icon: Radar,
      heroMetric: {
        val: summary?.kpis?.zero_day_detection_rate != null
          ? `${(summary.kpis.zero_day_detection_rate * 100).toFixed(1)}%`
          : '76.4%',
        label: 'Zero-Day Catch',
        sub: '2,725 / 3,568 novel unseen flows'
      },
      secondaryMetric: {
        val: summary?.kpis?.test_accuracy != null
          ? `${(summary.kpis.test_accuracy * 100).toFixed(1)}%`
          : '87.5%',
        label: 'Official Test Acc',
        sub: '84.1% Recall on test attacks'
      },
      metrics: [
        {
          label: 'Official Test Binary',
          val: summary?.kpis?.test_accuracy != null
            ? `${(summary.kpis.test_accuracy * 100).toFixed(2)}% Acc / ${(summary.kpis.test_recall != null ? (summary.kpis.test_recall * 100).toFixed(1) : '84.1')}% Rec`
            : '87.45% Acc / 84.1% Rec (Saved Ref)',
          sub: 'Official NSL-KDD test set (12,833 attacks)'
        },
        {
          label: 'Held-Out Zero-Day Catch',
          val: summary?.kpis?.zero_day_detection_rate != null
            ? `${(summary.kpis.zero_day_detection_rate * 100).toFixed(2)}%`
            : '76.37% (Saved Ref)',
          sub: '2,725 / 3,568 unseen novel attack flows detected'
        },
        {
          label: 'Explicit Zero-Day Screening',
          val: 'P: 51.6% · R: 49.4% · F1: 0.50',
          sub: 'Screening signal for analyst review, not verdict'
        },
      ],
      architectureNote: 'Implemented via scikit-learn MLPRegressor bottleneck reconstruction network (hidden layers: (64, 24, 8, 24, 64)) trained on benign traffic (X → X) coupled with an XGBoost classifier on 48 selected features. Novelty gate flags anomalies with weak known-class confidence (< 0.90) and reconstruction error exceeding threshold 0.2471465.',
      body: 'Combines an unsupervised MLPRegressor bottleneck reconstruction network baseline with supervised tree classifiers. Disaggregates official test accuracy from held-out zero-day capture and explicit zero-day screening signals, with SHAP feature attribution and reconstruction error decomposition.',
      futureResearch: [
        'GAN-based synthetic attack sample generation for augmenting low-density attack spaces.',
        'CTGAN and modern tabular generative models as alternatives for structured flow records.',
        'Targeted rare attack family detection, specifically addressing lower recall on R2L (~45%) and U2R (~66%).',
        'Improved unknown-attack generalisation across broader network topographies and protocol variations.',
        'Statistical concept drift detection for dynamically tracking shifting network flow distributions.',
        'Continual and incremental learning pipelines to incorporate verified new attack signatures without catastrophic forgetting.',
        'Confidence calibration (temperature/Platt scaling) and dynamic threshold optimisation.',
        'Evaluation on diverse, modern network intrusion corpora (CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15).'
      ],
      link: '/zero-day',
      linkLabel: 'Test in Zero-Day Studio',
    },
    {
      id: 'P2',
      title: 'Encrypted TLS / Traffic Threat Detection',
      shortTitle: 'Encrypted Inspection',
      tagline: 'Privacy-preserving TLS/QUIC detection without payload decryption via metadata dynamics',
      subtitle: 'Metadata-Driven Gradient-Boosted Trees (SPLT + JA4 + Transport Dynamics)',
      status: 'Validated Baseline',
      badgeClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
      icon: Lock,
      heroMetric: {
        val: '98.50%',
        label: 'Holdout Acc',
        sub: '234k flows / 9,948 groups'
      },
      secondaryMetric: {
        val: '1.72%',
        label: 'Benign FPR',
        sub: 'ROC-AUC 0.9988 reproducible'
      },
      metrics: [
        {
          label: 'Primary Reproducible Holdout',
          val: '98.50% Acc · 98.76% Rec',
          sub: '234,037 flows across 9,948 execution groups (Sept 2025)'
        },
        {
          label: 'Precision & F1 / Benign FPR',
          val: '97.99% Prec · 0.9837 F1 · 1.72% FPR',
          sub: 'ROC-AUC 0.9988 · PR-AUC 0.9984 (100% bit-for-bit reproducible)'
        },
        {
          label: 'Zero-Day Holdout Recall',
          val: '93.94% (697 / 742)',
          sub: '12 unseen malware families (Historical Draw 1: 97.99% Acc / 2.15% FPR)'
        },
      ],
      architectureNote: 'Designed around privacy-preserving encrypted-traffic metadata analysis without payload decryption (71-feature transformer: SPLT packet lengths/times, JA4 fingerprint prefix, cipher suite entropy, connection dynamics). Operates in offline flow record ingestion & calibrated preset mode.',
      scopeLimitation: 'The current implementation does NOT provide live network-interface traffic capture, arbitrary raw PCAP parsing/dissection (the /api/encrypted/analyze-pcap endpoint returns HTTP 501 Not Implemented), or payload decryption. Current detection operates exclusively on supplied pre-extracted connection metadata records.',
      body: 'Analyzes encrypted session dynamics using packet sequences and handshake telemetry without decrypting payload contents. Evaluated against a rigorous 234,037 holdout benchmark with 100% bit-for-bit reproducibility.',
      futureResearch: [
        'Live network-interface traffic capture (AF_PACKET / DPDK zero-copy drivers).',
        'PCAP upload, validation, and automated flow reassembly pipelines.',
        'Reliable bidirectional flow extraction and session tracking.',
        'Zeek / Scapy-based telemetry extraction where appropriate.',
        'TLS 1.3 and, where technically supported, QUIC transport metadata analysis (connection IDs, initial packet lengths).',
        'Real-time streaming feature extraction and sub-millisecond inference.',
        'Streaming traffic processing via Kafka / message queue ingestion.',
        'Encrypted-flow behavioural baselines and SNI reputation scoring.',
        'Performance and latency optimisation for multi-gigabit enterprise links (≥ 10 Gbps) [Provisional Engineering Target — To Be Validated].'
      ],
      link: '/encrypted',
      linkLabel: 'Open Encrypted Lab',
    },
    {
      id: 'P3',
      title: 'Alert Fatigue & Prioritisation',
      shortTitle: 'Contextual Triage',
      tagline: '5-factor mathematical risk scoring balancing confidence, anomaly, and asset criticality',
      subtitle: 'Class-Aware 5-Factor Composite Priority Score & Tiered Triage Engine',
      status: 'Validated Baseline',
      badgeClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
      icon: BellRing,
      heroMetric: {
        val: summary?.problem3?.workload?.auto_logged_share != null
          ? `${(summary.problem3.workload.auto_logged_share * 100).toFixed(1)}%`
          : '47.7%',
        label: 'Noise Filtered',
        sub: '10,746 flows safely auto-logged'
      },
      secondaryMetric: {
        val: summary?.problem3?.per_tier?.critical?.precision != null
          ? `${(summary.problem3.per_tier.critical.precision * 100).toFixed(1)}%`
          : '93.7%',
        label: 'Critical Precision',
        sub: '9,537 true attacks captured'
      },
      metrics: [
        {
          label: 'Safe Auto-Log Rate',
          val: summary?.problem3?.workload?.auto_logged_share != null
            ? `${(summary.problem3.workload.auto_logged_share * 100).toFixed(2)}%`
            : '47.67% (Saved Ref)',
          sub: '10,746 routine test flows filtered from human queue'
        },
        {
          label: 'Critical Tier Precision',
          val: summary?.problem3?.per_tier?.critical?.precision != null
            ? `${(summary.problem3.per_tier.critical.precision * 100).toFixed(2)}%`
            : '93.71% (Saved Ref)',
          sub: '9,537 true attacks captured in 10,177 critical alerts'
        },
        {
          label: 'Human Threat Preservation',
          val: summary?.problem3?.threat_preservation?.attacks_in_human_tiers != null
            ? `${(summary.problem3.threat_preservation.attacks_in_human_tiers * 100).toFixed(2)}%`
            : '85.43% (Saved Ref)',
          sub: '85.4% attacks & 78.2% zero-days reach human tiers (52.3% workload)'
        },
      ],
      architectureNote: 'Normalized 5-factor composite priority (class-aware confidence + reconstruction anomaly + threat severity + asset criticality + zero-day bonus). Features an unknown-service Review floor (0.5 default) and verified tier cutoffs: Critical (0.5901) and Review (0.1364).',
      scopeLimitation: 'Upstream Dependency: Prioritisation cannot recover threats missed by upstream detection. 14.6% of attacks (21.8% of zero-days) are auto-logged because both detectors confidently classified them as normal with near-zero anomaly error. Auto-logging is a triage tier, NOT a guarantee of benignness.',
      body: 'Reduces analyst alert fatigue by sorting flows into Critical, Review, and Auto-logged tiers using validation-derived quantiles, providing transparent tier reasons, component attribution, and data quality flags.',
      futureResearch: [
        'Cross-sensor alert correlation grouping related alerts across network sensors and endpoints.',
        'Temporal deduplication clustering repeated events from identical source/destination pairs.',
        'Incident-level risk aggregation across multi-stage attack campaigns.',
        'Context-sensitive false-positive reduction based on historical baseline suppressions.',
        'Asset inventory and CMDB integration (ServiceNow, Device42).',
        'Dynamic asset criticality factoring real-time crown-jewel tagging and exposure scores.',
        'Alert lifecycle management (state machine: New → Triage → Investigating → Resolved → Closed).',
        'SLA tracking, auto-assignment, and analyst workload distribution.',
        'Priority score explainability decomposing the 5 contributing terms for transparent auditability.',
        'Analyst feedback loops and interactive triage tuning to adapt weights to organizational risk tolerance.'
      ],
      link: '/alerts',
      linkLabel: 'Open Triage Console',
    },
    {
      id: 'P4',
      title: 'Adversarial Evasion Robustness',
      shortTitle: 'Adversarial Defense',
      tagline: 'Protocol-constrained perturbation synthesis & hardened retrained tree defenses',
      subtitle: 'Protocol-Constrained Perturbations & Adversarial Retraining (ε = 0.20 Benchmark)',
      status: 'Validated Baseline',
      badgeClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
      icon: ShieldAlert,
      heroMetric: {
        val: '+55.8%',
        label: 'FGSM Defense',
        sub: '+89.6% Universal Perturbations'
      },
      secondaryMetric: {
        val: '0.0%',
        label: 'FPR Penalty',
        sub: 'Clean recall preserved at 87.6%'
      },
      metrics: [
        {
          label: 'Evasion Mitigation',
          val: summary?.adversarial?.summary?.evasion_reduction_pct != null
            ? `+${summary.adversarial.summary.evasion_reduction_pct}%`
            : '+28.8% DEMGAN / +55.8% FGSM / +89.6% UAP',
          sub: 'Hybrid evasion drop across FGSM, UAP & DEMGAN surrogate'
        },
        {
          label: 'Clean Recall Preserved',
          val: summary?.adversarial?.summary?.hardened_attack_recall != null
            ? `${(summary.adversarial.summary.hardened_attack_recall * 100).toFixed(1)}%`
            : '87.60% (Clean Acc: 89.77%)',
          sub: 'Zero clean performance degradation (-0.07% abs delta)'
        },
        {
          label: 'False Alarm Penalty',
          val: summary?.adversarial?.clean_metrics?.fpr_penalty != null
            ? `${(summary.adversarial.clean_metrics.fpr_penalty * 100).toFixed(1)}%`
            : '0.0% Penalty (FPR: 8.07%)',
          sub: '100.0% network protocol constraint validity'
        },
      ],
      architectureNote: 'Evaluates two-sided numerical Constrained FGSM, Universal Adversarial Perturbations (UAP), and DEMGAN empirical manifold drift approximation. The XGBoost classifier is retrained on 149,973 samples, backed by the MLPRegressor bottleneck reconstruction anomaly gate as defense-in-depth.',
      scopeLimitation: 'DEMGAN Implementation Note: The current DEMGAN implementation is an empirical manifold-drift surrogate approximation drifting features toward benign centroids with calibrated jitter, NOT a trained neural GAN generator. No neural GAN generator exists in the current codebase. PGD is verified as unimplemented and excluded.',
      body: 'Hardens tree-ensembles against gradient and distribution perturbations under strict protocol constraints (clamped rates, discrete counts, TCP/UDP semantics, header immutability), maintaining clean detection accuracy without false alarm penalties.',
      futureResearch: [
        'Fully trained GAN-based synthetic network traffic generation (see dedicated research section below).',
        'CTGAN and modern tabular generative models for structured network-flow data.',
        'Synthetic rare-attack generation focusing on low-support classes (R2L, U2R).',
        'Adversarial sample generation for systematic detector stress-testing.',
        'Domain-constrained generation preserving valid feature and protocol relationships.',
        'Systematic adversarial retraining experiments using generated samples.',
        'Evaluation of generated-data realism and sample diversity (Wasserstein distance, Jensen-Shannon divergence).',
        'Direct empirical comparison against SMOTE, ADASYN, and heuristic augmentation baselines.',
        'Verification against train/test contamination and data leakage.',
        'Evaluation on untouched chronological splits and family-held-out zero-day datasets.'
      ],
      link: '/adversarial',
      linkLabel: 'Open Defense Studio',
    },
  ]

  // ---------------------------------------------------------------------------
  // 2. Sequential Development Stages (1 through 6)
  // Reflects the verified project state without claiming unverified completion
  // ---------------------------------------------------------------------------
  const developmentStages = [
    {
      stageNumber: 1,
      stage: 'Stage 1',
      title: 'Product Discovery & Architecture',
      status: 'In Progress (Planning Baseline)',
      badgeClass: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
      oneLiner: 'Complete codebase audit, target SecOps workflow definitions, and tenant-aware decoupled architecture.',
      focusAreas: ['Codebase Audit', 'Tenant Data Isolation (10 Boundaries)', 'OpenAPI 3.1 Specs', 'Threat Modeling'],
      workstreams: ['WS-1 Security Architecture', 'WS-6 Triage Engine', 'WS-9 Infrastructure', 'WS-11 ADR Specs'],
      summary: 'Complete codebase audit, target customer & SOC workflow definition, modular decoupling, and tenant-aware architecture (Reconciled Phase 2A Backlog v2.1.0).',
      objectives: [
        'Execute complete repository and capability audit verifying baseline models, data pipelines, and limitations.',
        'Define target customer profiles and SecOps analyst workflows (Tier 1 triage, Tier 2 forensics, SOC Lead, CISO).',
        'Establish modular decoupled service boundaries and microservice contracts.',
        'Design multi-tenant architecture and strict tenant-level cryptographic data isolation boundaries (10 security boundaries) upfront.',
        'Publish formal OpenAPI 3.1 contracts and standardized event schemas (OCSF / ECS).',
        'Conduct security threat modelling (STRIDE, zero-trust data boundaries) across all ingestion and API paths.',
        'Establish Model Intelligence and Lifecycle Management framework design (dataset governance, registry, drift, retraining policies).',
        'Establish research, testing, CI/CD pipeline, and model governance standards.'
      ],
      dependencies: 'Completion of academic research baseline and initial code modularization.',
      acceptanceCriteria: [
        'Formal architectural specification document approved by technical and security leads.',
        'OpenAPI 3.1 contracts published for ingestion, detection, triage, and management interfaces.',
        'Tenant data isolation specification formally approved prior to SaaS customer onboarding.',
        'Automated CI pipeline operational with static application security testing (SAST) and license audits.'
      ],
      prerequisite: 'Approved API schemas, decoupled service boundaries, tenant isolation blueprint, and threat model.',
    },
    {
      stageNumber: 2,
      stage: 'Stage 2',
      title: 'Strengthen Existing Capabilities',
      status: 'Current Operational Baseline',
      badgeClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
      oneLiner: 'Harden and decouple the four validated problem engines into independently testable services with reproducible benchmarks.',
      focusAreas: ['Decoupled ML Services', 'Bit-for-Bit Benchmarks', 'Rare Attack Research', 'Inference Optimization'],
      workstreams: ['WS-2 Backend Reliability', 'WS-7 Model Governance', 'WS-8 Adversarial Defense', 'WS-10 Testing QA'],
      summary: 'Harden and decouple the four validated problem engines into independently testable services with reproducible benchmarks.',
      objectives: [
        'Decouple detection engines into independent, stateless services with isolated virtual environments.',
        'Establish automated, bit-for-bit reproducible benchmarks across both NSL-KDD and Stratosphere TLS corpora.',
        'Standardize detection evaluation metrics (ROC-AUC, PR-AUC, F1, latency per flow, memory footprint).',
        'Preserve all validated baseline model weights, feature transformers, and threshold tuning scripts.',
        'Conduct targeted rare attack detection research addressing lower recall on R2L and U2R families.',
        'Execute GAN/CTGAN feasibility experiments for synthetic flow generation versus SMOTE baselines.',
        'Conduct adversarial generation and retraining research beyond empirical surrogates.',
        'Advance model explainability across detection (SHAP), anomaly gating, and composite priority scoring.',
        'Initiate concept drift and continual learning experiments without catastrophic forgetting.',
        'Optimise inference performance and latency [Provisional Engineering Target — To Be Validated: sub-5ms CPU model inference latency per flow, distinct from end-to-end pipeline latency].',
        'Establish Model Registry & experiment governance tracking weights, feature transformer compatibility, hyperparameters, and artifact lineages.'
      ],
      dependencies: 'Stage 1 architectural contracts, test harness, and evaluation standards.',
      acceptanceCriteria: [
        '100% of existing unit and regression tests pass; bit-for-bit benchmark reproducibility validated.',
        'Sub-5ms single-core CPU model inference latency per flow [Provisional Engineering Target — To Be Validated; distinct from end-to-end pipeline latency].',
        'Zero performance regression on clean attack recall or adversarial evasion mitigation across retraining.',
        'Empirical GAN vs. SMOTE feasibility report completed with leakage and constraint audits.'
      ],
      prerequisite: 'Decoupled service packaging, verified benchmark reproduction scripts, and zero functional regression.',
    },
    {
      stageNumber: 3,
      stage: 'Stage 3',
      title: 'Core SecOps Operations Expansion',
      status: 'Planned Engineering',
      badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
      oneLiner: 'Implement live security data ingestion, event normalization, multi-sensor correlation, and incident tracking.',
      focusAreas: ['Live NIC Capture / PCAP', 'OCSF Normalization', 'Alert Correlation', 'STIX/TAXII Threat Intel'],
      workstreams: ['WS-3 Persistence', 'WS-4 Frontend Client', 'WS-5 Encrypted Telemetry', 'WS-6 Triage Engine'],
      summary: 'Build reliable security data ingestion, event normalization, multi-sensor correlation, and incident tracking.',
      objectives: [
        'Implement live network-interface traffic capture (AF_PACKET / DPDK) and PCAP upload processing.',
        'Build reliable bidirectional flow extraction and real-time streaming feature processing.',
        'Deploy streaming inference engine supporting high-throughput flow scoring with backpressure handling.',
        'Implement event normalization and enrichment (OCSF/ECS schemas, GeoIP, ASN lookup).',
        'Introduce multi-sensor alert correlation and temporal deduplication clustering related events into incidents.',
        'Expand incident management: attack timelines, evidence binders, and MITRE ATT&CK mapping.',
        'Threat intelligence lifecycle management: STIX/TAXII 2.1 IOC ingestion, matching, and aging.',
        'Implement initial enterprise Role-Based Access Control (RBAC) and immutable audit logging.'
      ],
      dependencies: 'Stage 2 stabilized detection microservices and persistent database storage.',
      acceptanceCriteria: [
        'Sustained streaming ingestion throughput ≥ 10,000 events/sec with backpressure handling [Provisional Engineering Target — To Be Validated].',
        'Multi-sensor alert correlation achieves ≥ 60% reduction in raw alert volume into grouped incident entities [Provisional Engineering Target — To Be Validated].',
        '100% audit trail logging of all triage modifications and analyst status transitions.',
        'Verified STIX/TAXII 2.1 feed ingestion matching IOCs against active flow telemetry.'
      ],
      prerequisite: 'Validated end-to-end ingestion-to-incident lifecycle with external SIEM/SOAR connector prototypes.',
    },
    {
      stageNumber: 4,
      stage: 'Stage 4',
      title: 'Enterprise and SaaS Readiness',
      status: 'Planned Engineering',
      badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
      oneLiner: 'Enforce multi-tenant cryptographic isolation, organization management, secure auth, scalability, and compliance.',
      focusAreas: ['10 Isolation Boundaries', 'Cross-Tenant Test Suite', 'SSO / MFA / RBAC', 'High Availability & DR'],
      workstreams: ['WS-1 Security & Auth', 'WS-3 Persistence', 'WS-9 Infrastructure', 'WS-10 Testing QA'],
      summary: 'Enforce multi-tenant data isolation, organization management, secure auth, scalability, encryption, and operational resilience.',
      objectives: [
        'Implement all 10 platform security boundaries: database-level, object storage, cache/queue, API auth, background jobs, model datasets/artifacts, logs/backups, administrative RBAC, secrets management, and tenant auditability.',
        'Implement automated negative authorization test suite verifying zero cross-tenant access across IDOR, API endpoints, background jobs, exports, admin functions, and model retrieval.',
        'Build organization and workspace management supporting multi-team and MSSP deployments.',
        'Deploy secure authentication (SSO via SAML 2.0 / OIDC, MFA) and session management.',
        'Deploy API gateway with scoped keys, rate limiting, and tenant usage quotas.',
        'Develop Infrastructure-as-Code (IaC) deployment automation (Kubernetes Helm charts, Terraform).',
        'Conduct scalability load testing validating horizontal worker autoscaling under peak volumes.',
        'Implement high availability (HA), automated backups, and disaster recovery (DR) playbooks.',
        'Enforce security compliance: data retention policies, cold archival, AES-256 rest / TLS 1.3 transit encryption.',
        'Deploy operational observability: Prometheus metrics endpoints, Grafana dashboards, and tracing.',
        'Establish production Model Registry with canary deployment gates, automated model rollback, and performance drift alerts.',
        'Execute third-party penetration testing, vulnerability assessments, and SOC 2 / ISO 27001 readiness audits.'
      ],
      dependencies: 'Stage 3 SecOps engine and data normalization services.',
      acceptanceCriteria: [
        '99.9% platform availability under synthetic sustained load during 7-day endurance testing [Provisional Engineering Target — To Be Validated].',
        'RTO ≤ 15 minutes and RPO ≤ 5 minutes validated during simulated disaster recovery drills [Provisional Engineering Target — To Be Validated].',
        'Zero High or Critical vulnerabilities in independent third-party penetration testing.',
        'Tenant data isolation verified by automated cross-tenant penetration test harness with zero cross-tenant access findings.'
      ],
      prerequisite: 'SOC 2 Type 1 / ISO 27001 readiness review and production deployment sign-off.',
    },
    {
      stageNumber: 5,
      stage: 'Stage 5',
      title: 'Governed AI Integration',
      status: 'Long-Term Exploratory Vision',
      badgeClass: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30',
      oneLiner: 'Augment SecOps workflows with evidence-grounded generative AI assistance under strict human oversight.',
      focusAreas: ['AI Analyst Assistant', 'Text-to-Query Investigation', 'Automated Summarization', 'Prompt-Injection Defense'],
      workstreams: ['WS-7 Model Governance', 'WS-8 Adversarial Hardening', 'WS-1 Security Architecture'],
      summary: 'Augment SecOps workflows with evidence-grounded generative AI assistance under strict human oversight. (Optional parallel workstream that does not block core product experience or pilot preparation).',
      objectives: [
        'Develop AI Security Analyst Assistant for natural-language incident explanations and guidance.',
        'Implement natural-language threat investigation converting questions into optimized queries (Text-to-SQL/ES).',
        'Build automated incident summarisation generating executive handoff reports and shift notes.',
        'Deploy AI-assisted detection rule drafting with sandbox syntax validation (Sigma / YARA-L).',
        'Implement supervised agentic investigation workflows operating strictly under human approval.',
        'Enforce evidence-grounded assistance: AI cannot declare authoritative conclusions without verifiable evidence.',
        'Establish AI Governance Framework: prompt-injection sanitization, tenant-isolated RAG, and audit trails.'
      ],
      dependencies: 'Stage 4 hardened enterprise architecture, RBAC, and contextual incident stores.',
      acceptanceCriteria: [
        'Strict human oversight: 100% of containment actions require affirmative analyst approval.',
        'Prompt-injection defense evaluation achieves ≥ 99% mitigation on standard red-team jailbreaks [Provisional Engineering Target — To Be Validated].',
        'Analyst evaluation demonstrates ≥ 35% reduction in mean time to understand (MTTU) incidents [Provisional Engineering Target — To Be Validated].',
        '100% of AI-generated incident hypotheses are mapped to verifiable telemetry evidence.'
      ],
      prerequisite: 'AI Safety Council certification, model hallucination bounds audit, and red-team sign-off.',
    },
    {
      stageNumber: 6,
      stage: 'Stage 6',
      title: 'Product Experience & Commercialization',
      status: 'Long-Term Exploratory Vision',
      badgeClass: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
      oneLiner: 'Complete enterprise UI/UX redesign, execute design-partner pilot deployments, and validate commercial viability.',
      focusAreas: ['Enterprise SOC UX', 'Multi-Hop Attack Graphs', 'Authorized Pilot Deployments', 'SaaS Packaging'],
      workstreams: ['WS-4 Frontend Client', 'WS-11 Commercial Packaging', 'WS-10 Testing QA'],
      summary: 'Complete enterprise UI/UX redesign, execute design-partner pilot deployments, and validate commercial viability. (UI/UX development, investigation workspaces, usability testing, and pilot onboarding proceed independently of AI assistant capabilities; AI can be integrated in parallel when validated).',
      objectives: [
        'Deliver complete enterprise UI/UX redesign with customizable multi-tenant SOC dashboards (independent of AI integration).',
        'Build interactive attack graph visualizer mapping complex multi-hop cyber kill chains.',
        'Conduct formal usability testing and cognitive walkthroughs with active SOC analysts.',
        'Execute authorized organizational pilot deployments with enterprise security partners.',
        'Onboard multi-tenant pilot organizations with self-service administration and usage tracking.',
        'Empirically measure operational impact: MTTD, MTTR, and analyst triage time reduction.',
        'Finalize commercial SaaS packaging: licensing models, support tiers, and SLA specifications.'
      ],
      dependencies: 'Stage 4 enterprise foundation and tenant isolation, Stage 3 core SecOps workflows, and Stage 2 validated detection models. (Stage 5 Governed AI is an optional parallel workstream that can be integrated when validated, but does not block UI/UX development, usability testing, or core pilot deployments).',
      acceptanceCriteria: [
        'Successful completion of at least 3 authorized pilot deployments in active enterprise SOCs.',
        'Empirically documented ≥ 40% reduction in analyst alert triage time compared to baseline [Provisional Engineering Target — To Be Validated].',
        'Customer Net Promoter Score (NPS) ≥ 50 with commercial pilot conversion readiness [Provisional Engineering Target — To Be Validated].',
        'Commercial packaging, support tiers, and SLA commitments signed off by stakeholders.'
      ],
      prerequisite: 'Pilot evaluation sign-off, commercial pricing model approval, and GA readiness review.',
    },
  ]

  // ---------------------------------------------------------------------------
  // 3. Real Interactive Dependency Map (Reconciled Phase 2A Backlog)
  // Grounded 100% in AEGIS_ENGINEERING_BACKLOG.md (31 tasks, 11 workstreams, 4 milestones)
  // ---------------------------------------------------------------------------
  const dependencyWorkstreams: DependencyWorkstream[] = [
    {
      id: 'WS-SEC-AUTH',
      code: 'SEC',
      name: 'Authentication & Session Architecture',
      milestone: 'M1',
      milestoneTitle: 'Milestone 1: Core Foundation',
      category: 'Security & Auth',
      status: 'Ready / Foundation',
      badgeClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
      tasks: [
        { id: 'SEC-01', name: 'HttpOnly Access JWT + SQLite Server-Side Session Tracking', priority: 'P0', cvss: '8.8' },
        { id: 'SEC-02', name: 'Enforce TLS Certificate Verification for Elasticsearch Default', priority: 'P0', cvss: '7.5' }
      ],
      prerequisites: [],
      unblocks: ['WS-SEC-TRANSPORT', 'WS-PRI-TRIAGE', 'WS-INF-DOCKER', 'WS-BE-RATE'],
      description: 'Establishes secure authentication foundation: short-lived 15m JWT stored in HttpOnly cookies, server-side SQLite session revocation table, CSPRNG CSRF token validation, and secure TLS certificate verification defaults for Elasticsearch.',
      risk: 'RSK-01: Existing frontend calls breaking due to missing cookies or CSRF token mismatch. Mitigated via Axios withCredentials and interceptors.',
      acceptanceCriteria: [
        'Requests to /api/dashboard/stats without valid session cookie return HTTP 401.',
        'Session revocation endpoint immediately invalidates session in SQLite store.',
        'ELASTICSEARCH_VERIFY_CERTS evaluates to True by default in config.py.'
      ]
    },
    {
      id: 'WS-BE-FALLBACK',
      code: 'BE',
      name: 'Durable Fallback & Backend Reliability',
      milestone: 'M1',
      milestoneTitle: 'Milestone 1: Core Foundation',
      category: 'Persistence',
      status: 'Ready / Foundation',
      badgeClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
      tasks: [
        { id: 'BE-03', name: 'Durable SQLite-Backed Fallback Persistence with WAL Mode', priority: 'P0', cvss: '7.5' },
        { id: 'BE-01', name: 'Defensive Metrics Loading Guard Against NoneType Exceptions', priority: 'P1' }
      ],
      prerequisites: [],
      unblocks: ['WS-DB-STORAGE', 'WS-PRI-TRIAGE'],
      description: 'Guarantees zero alert loss when Elasticsearch is unavailable by maintaining a local SQLite store in WAL mode, coupled with background synchronization worker that replays alerts upon cluster reconnection.',
      risk: 'RSK-02: SQLite database locking under concurrent batch ingestion. Mitigated by Write-Ahead Logging (WAL) and busy_timeout=5000.',
      acceptanceCriteria: [
        'Stopping Elasticsearch container and ingesting 50 alerts persists all 50 in aegis_fallback.db.',
        'Reconnecting Elasticsearch replays unsynced alerts without data loss or duplication.',
        'Missing metrics.json file triggers graceful fallback without NoneType 500 errors.'
      ]
    },
    {
      id: 'WS-FE-CONFIG',
      code: 'FE',
      name: 'Client API Configuration & Pytest Harness',
      milestone: 'M1',
      milestoneTitle: 'Milestone 1: Core Foundation',
      category: 'Reliability',
      status: 'Ready / Foundation',
      badgeClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
      tasks: [
        { id: 'FE-02', name: 'Configurable API Base URL, Environment Discovery & Axios Config', priority: 'P2' },
        { id: 'BE-02', name: 'Standardize Test Imports & pyproject.toml Execution Root', priority: 'P1' }
      ],
      prerequisites: [],
      unblocks: ['WS-ENC-PCAP', 'WS-TST-HARNESS'],
      description: 'Standardizes frontend HTTP transport with runtime API discovery and credential support; establishes standardized pyproject.toml for unified test execution across all modules.',
      risk: 'Configuration drift between local dev and containerized reverse proxies. Mitigated by fallback hierarchy.',
      acceptanceCriteria: [
        'Axios client includes withCredentials: true and extracts X-CSRF-Token automatically.',
        'pytest executes from repository root without PYTHONPATH manual exports.',
        'All 88 existing backend unit tests execute cleanly.'
      ]
    },
    {
      id: 'WS-SEC-TRANSPORT',
      code: 'SEC',
      name: 'Transport Hardening & Browser Headers',
      milestone: 'M2',
      milestoneTitle: 'Milestone 2: Transport & De-risking',
      category: 'Security & Auth',
      status: 'Dependent',
      badgeClass: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
      tasks: [
        { id: 'SEC-04', name: 'Restrict Permissive CORS Policy & Enforce Method/Auth Guards', priority: 'P1', cvss: '5.3' },
        { id: 'SEC-05', name: 'Security Response Headers Middleware (OWASP Defense)', priority: 'P2', cvss: '4.3' }
      ],
      prerequisites: ['WS-SEC-AUTH'],
      unblocks: ['WS-BE-RATE'],
      description: 'Enforces strict CORS origin whitelisting, method verification, and OWASP defensive HTTP headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) across all API endpoints.',
      risk: 'Overly strict CSP blocking Swagger UI or CDN assets. Mitigated by script-src whitelist for Swagger.',
      acceptanceCriteria: [
        'Disallowed origins receive no Access-Control-Allow-Origin header.',
        'All HTTP responses include security defensive headers.',
        'Swagger UI at /docs renders without CSP violations.'
      ]
    },
    {
      id: 'WS-ENC-PCAP',
      code: 'ENC',
      name: 'Encrypted Traffic Interface De-risking',
      milestone: 'M2',
      milestoneTitle: 'Milestone 2: Transport & De-risking',
      category: 'Reliability',
      status: 'Dependent',
      badgeClass: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
      tasks: [
        { id: 'ENC-01', name: 'Formalize /api/encrypted/analyze-pcap as RFC 7807 501 Spec', priority: 'P1' },
        { id: 'FE-01', name: 'Remove Misleading Raw PCAP UI & Display Stage 3 Roadmap Banner', priority: 'P1' },
        { id: 'ENC-02', name: 'Network Sniffer Decoupling Tooltip & Architecture Note', priority: 'P3' }
      ],
      prerequisites: ['WS-FE-CONFIG'],
      unblocks: [],
      description: 'Eliminates misleading UI by disabling raw PCAP drag-and-drop, surfacing prominent Stage 3 roadmap banners, and standardizing RFC 7807 501 Not Implemented responses for unbuilt endpoints.',
      risk: 'RSK-04: Users perceiving removal of PCAP dropzone as loss of capability. Mitigated by highlighting synthetic presets.',
      acceptanceCriteria: [
        'PCAP dropzone removed from EncryptedLab; pre-extracted metadata flows remain 100% operational.',
        '/analyze-pcap endpoint returns RFC 7807 problem details with HTTP 501 status.',
        'Roadmap banner clearly explains live capture & flow reassembly is scheduled for Stage 3.'
      ]
    },
    {
      id: 'WS-DB-STORAGE',
      code: 'DB',
      name: 'Storage Retention, Eviction & Index Templates',
      milestone: 'M2',
      milestoneTitle: 'Milestone 2: Transport & De-risking',
      category: 'Persistence',
      status: 'Dependent',
      badgeClass: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
      tasks: [
        { id: 'DB-02', name: 'Storage Retention Policy, WAL Maintenance & Disk Pressure Handling', priority: 'P1' },
        { id: 'DB-01', name: 'Elasticsearch Index Template & Version-Pinned Schema Mapping', priority: 'P2' }
      ],
      prerequisites: ['WS-BE-FALLBACK'],
      unblocks: [],
      description: 'Enforces durable storage limits: 250 MiB byte budget, 50,000 alert ceiling, 1 GiB free disk guardrail, 10% emergency critical reserve, and version-pinned Elasticsearch index templates.',
      risk: 'Disk exhaustion during alert flooding. Mitigated by HTTP 507 backpressure rejection.',
      acceptanceCriteria: [
        'Fallback storage automatically prunes synchronized non-critical alerts when exceeding 250 MiB.',
        'Never silently drops critical, unreviewed, or unsynchronized alerts.',
        'Elasticsearch indices initialized with explicit strict schema mapping.'
      ]
    },
    {
      id: 'WS-PRI-TRIAGE',
      code: 'PRI',
      name: 'Persistent Incident Triage State Machine',
      milestone: 'M3',
      milestoneTitle: 'Milestone 3: Operations & QA',
      category: 'Reliability',
      status: 'Dependent',
      badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
      tasks: [
        { id: 'PRI-02', name: 'Persistent Alert Triage Lifecycle & Analyst State Mutation API', priority: 'P1' },
        { id: 'PRI-01', name: 'Centralize Asset Criticality Floor Helper Across Routers', priority: 'P2' }
      ],
      prerequisites: ['WS-SEC-AUTH', 'WS-BE-FALLBACK'],
      unblocks: ['WS-ML-GOV', 'WS-ADV-CLAMP'],
      description: 'Introduces stateful analyst triage lifecycle (New → Triage → Investigating → Resolved → Closed) backed by persistent storage with immutable analyst audit notes.',
      risk: 'Concurrent analyst status collisions. Mitigated by optimistic locking or audit versioning.',
      acceptanceCriteria: [
        'PATCH /api/dashboard/alerts/{id}/triage persists status and analyst notes.',
        'Triage mutations persist across server restarts and page reloads.',
        'Unknown service floor helper uniformly applied across all priority calculations.'
      ]
    },
    {
      id: 'WS-INF-DOCKER',
      code: 'INF',
      name: 'Docker Isolation & Safe Process Management',
      milestone: 'M3',
      milestoneTitle: 'Milestone 3: Operations & QA',
      category: 'Infrastructure',
      status: 'Dependent',
      badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
      tasks: [
        { id: 'INF-01', name: 'Docker Compose Network Isolation, Auth & Healthchecks', priority: 'P1' },
        { id: 'INF-02', name: 'Reliable Cross-Platform Process Management Scripts', priority: 'P2' }
      ],
      prerequisites: ['WS-SEC-AUTH'],
      unblocks: [],
      description: 'Secures container topology by unbinding Elasticsearch from public host interfaces, running on internal Docker bridge networks, and enhancing Windows startup scripts with PID verification.',
      risk: 'Port conflicts with existing host services. Mitigated by PID-based tracking.',
      acceptanceCriteria: [
        'Elasticsearch port 9200 unexposed to external network interfaces.',
        'check_aegis.bat and stop_aegis.bat target only verified AEGIS-owned PIDs.',
        'Docker compose healthchecks report container readiness accurately.'
      ]
    },
    {
      id: 'WS-TST-HARNESS',
      code: 'TST',
      name: 'Test Isolation & Vitest Component Suite',
      milestone: 'M3',
      milestoneTitle: 'Milestone 3: Operations & QA',
      category: 'Testing & QA',
      status: 'Dependent',
      badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
      tasks: [
        { id: 'TST-01', name: 'Elasticsearch Test Index Isolation & Ephemeral Fixtures', priority: 'P1' },
        { id: 'TST-02', name: 'Frontend Unit Testing Harness Setup with Vitest', priority: 'P2' },
        { id: 'TST-03', name: 'Unified Test Launcher Script Across Backend & Frontend', priority: 'P2' }
      ],
      prerequisites: ['WS-FE-CONFIG'],
      unblocks: [],
      description: 'Isolates integration testing onto ephemeral UUID indices (aegis-alerts-test-{uuid}) preventing test contamination; establishes Vitest test harness for frontend components.',
      risk: 'Slow test run times with Docker integration. Mitigated by ephemeral fixtures with auto-teardown.',
      acceptanceCriteria: [
        'Integration tests never modify production aegis-alerts index.',
        'npm test executes React component unit tests successfully.',
        'Unified test runner script executes full test suite and outputs exit code 0.'
      ]
    },
    {
      id: 'WS-ML-GOV',
      code: 'ML',
      name: 'Cryptographic Model Manifest & Drift Telemetry',
      milestone: 'M4',
      milestoneTitle: 'Milestone 4: Enterprise Prep',
      category: 'ML Governance',
      status: 'Planned',
      badgeClass: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
      tasks: [
        { id: 'SEC-03', name: 'Cryptographic Manifest Verification for Serialized ML Artifacts', priority: 'P2', cvss: '7.2' },
        { id: 'ML-01', name: 'Feature Drift & Novelty Quantile Telemetry Logging', priority: 'P2' },
        { id: 'ML-02', name: 'Categorical Feature Encoding Guard & Schema Validation', priority: 'P2' },
        { id: 'BE-05', name: 'Asynchronous Model Loading & Liveness Startup Probe', priority: 'P2' }
      ],
      prerequisites: ['WS-PRI-TRIAGE'],
      unblocks: [],
      description: 'Enforces cryptographically signed HMAC manifests on all serialized .joblib model files prior to unpickling; logs hourly distribution drift telemetry to detect concept shift.',
      risk: 'RSK-05: Retrained model fails to load because developer forgot to sign manifest. Mitigated by build script.',
      acceptanceCriteria: [
        'Tampered or unsigned model files raise SecurityException and abort loading.',
        'Hourly background worker logs PSI and Wasserstein drift metrics for input features.',
        'Async model loading keeps health probe responsive during startup.'
      ]
    },
    {
      id: 'WS-ADV-CLAMP',
      code: 'ADV',
      name: 'Adversarial Gradient Clamping & Protocols',
      milestone: 'M4',
      milestoneTitle: 'Milestone 4: Enterprise Prep',
      category: 'ML Governance',
      status: 'Planned',
      badgeClass: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
      tasks: [
        { id: 'ADV-01', name: 'Clamp Adversarial Feature Perturbations to Valid Protocol Bounds', priority: 'P2' },
        { id: 'ADV-02', name: 'Formalize DEMGAN Manifold Drift Surrogate Documentation & Tests', priority: 'P2' }
      ],
      prerequisites: ['WS-PRI-TRIAGE'],
      unblocks: [],
      description: 'Ensures adversarial perturbation generators strictly clamp mutated values within valid network protocol bounds (rate limits, integer counts, header flags) and clarifies DEMGAN empirical surrogate bounds.',
      risk: 'RSK-06: Clamping altering verified evasion rates. Mitigated by full test_adversarial.py regression suite.',
      acceptanceCriteria: [
        'Adversarial perturbations never produce impossible negative packet counts or rate breaches.',
        'DEMGAN explicitly tested and documented as empirical surrogate manifold drift.',
        'Zero clean recall regression on hardened model evaluations.'
      ]
    },
    {
      id: 'WS-BE-RATE',
      code: 'BE',
      name: 'Inference Throttling & OpenAPI 3.1 Specs',
      milestone: 'M4',
      milestoneTitle: 'Milestone 4: Enterprise Prep',
      category: 'Reliability',
      status: 'Planned',
      badgeClass: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
      tasks: [
        { id: 'BE-04', name: 'Rate Limiting on Computationally Expensive Simulation Endpoints', priority: 'P2' },
        { id: 'DOC-01', name: 'Synchronize OpenAPI Documentation with Running Endpoints', priority: 'P2' },
        { id: 'DOC-02', name: 'Formalize Architecture Decision Records (ADRs 001-008)', priority: 'P3' }
      ],
      prerequisites: ['WS-SEC-AUTH', 'WS-SEC-TRANSPORT'],
      unblocks: [],
      description: 'Implements Slowapi rate limiting on resource-intensive batch inference and adversarial simulation endpoints; publishes complete OpenAPI 3.1 schemas and formal ADR records.',
      risk: 'Throttling legitimate analyst batch simulations. Mitigated by configurable analyst quotas.',
      acceptanceCriteria: [
        'Exceeding 20 simulation requests/min returns HTTP 429 Too Many Requests.',
        'OpenAPI /docs schema matches 100% of live query parameters and error models.',
        'Formal ADR records recorded for authentication, fallback, and PCAP decisions.'
      ]
    }
  ]

  // ---------------------------------------------------------------------------
  // 4. Functional Capability Modules (A through H)
  // Organized into 4 capability clusters for clear visual architecture
  // ---------------------------------------------------------------------------
  const moduleClusters = [
    {
      clusterName: 'Data Collection & Ingestion',
      clusterDesc: 'Network interface capture, logs, queues, and event normalization',
      color: 'amber',
      modules: [
        {
          letter: 'A',
          title: 'Security Data Collection & Ingestion',
          category: 'Telemetry & Ingestion',
          icon: Database,
          status: 'Planned Engineering',
          badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
          currentVerified: 'Offline CSV batch ingestion, NSL-KDD benchmark replay, and synthetic flow presets.',
          missingWork: 'Live network-interface packet capture, PCAP parsing, streaming queues, and OCSF normalization.',
          targetStage: 'Stage 3 & Stage 4',
          dependencies: 'Network driver bindings, message broker (Kafka)',
          acceptanceSummary: '≥ 10,000 events/sec sustained ingestion [Provisional Engineering Target]',
          scope: [
            'Live network-interface traffic capture via zero-copy drivers (AF_PACKET / DPDK).',
            'PCAP upload, validation, parsing, and automated flow reassembly pipelines.',
            'High-throughput NetFlow (v5/v9), IPFIX, sFlow, and cloud VPC flow log ingestion.',
            'Firewall, endpoint, server, and cloud audit logs (Syslog, Windows EVTX, auditd, cloud trails).',
            'Zeek and Suricata security telemetry extraction and flow enrichment.',
            'Scalable streaming ingestion via distributed message queues (Kafka / RabbitMQ / Redis Streams).',
            'Event normalization to open standards (Open Cybersecurity Schema Framework OCSF / Elastic ECS).',
            'Network context enrichment: GeoIP, autonomous system numbers (ASN), and reverse DNS resolution.',
            'Data validation, schema sanitization, and graceful malformed-record dead-letter handling.',
            'Policy-driven data tiering (hot/warm/cold), automated archival, and AES-256 / TLS 1.3 encryption.',
            'Extensible connector ecosystem supporting modular REST APIs, webhooks, and rate-limited endpoints.'
          ],
        }
      ]
    },
    {
      clusterName: 'Core Analytics & Threat Intelligence',
      clusterDesc: 'Multi-tiered detection, machine learning, and alert prioritization',
      color: 'emerald',
      modules: [
        {
          letter: 'B',
          title: 'Threat Detection & Analytics',
          category: 'Analytics Engine & Model Intelligence',
          icon: Radar,
          status: 'Implemented (Partial Baseline)',
          badgeClass: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
          currentVerified: 'P1 MLPRegressor bottleneck reconstruction network + XGBoost hybrid detector, P2 SPLT + JA4 encrypted flow classifier, P4 adversarially retrained hardened detector.',
          missingWork: 'Live flow feature extraction, GAN/CTGAN generative research, UEBA behavioral baselines, threat intel feeds, Sigma rule engine, and Model Lifecycle Management.',
          targetStage: 'Stage 2 & Stage 3',
          dependencies: 'Decoupled ML services, feature transformer contracts',
          acceptanceSummary: 'Sub-5ms model inference latency per flow; zero regression on clean recall',
          scope: [
            'Known attack family detection via supervised tree-ensembles (Validated in P1/P2).',
            'Anomaly and novel attack pattern detection via MLPRegressor bottleneck reconstruction network (Validated in P1).',
            'Encrypted traffic behavioral threat analysis without payload decryption (Validated in P2).',
            'Adversarial evasion hardening and constrained retraining (Validated in P4).',
            'GAN/CTGAN research for synthetic network traffic generation & stress testing (Experimental Research).',
            'Targeted rare attack detection focusing on low-support classes (R2L and U2R).',
            'Unknown attack discovery and automated novel threat candidate clustering.',
            'Statistical concept drift detection for dynamically tracking shifting traffic distributions.',
            'Continual and incremental learning to adapt models without catastrophic forgetting.',
            'Behavioral threat analytics: User & Entity Behavior Analytics (UEBA) and baseline deviations.',
            'Beaconing frequency analysis, long-tail connection anomalies, and lateral movement detection.',
            'Threat intelligence lifecycle management: STIX/TAXII 2.1 IOC ingestion, matching, and aging.',
            'Detection engineering: custom Sigma and YARA-L rules engine with version control and testing.',
            'Dataset & Experiment Governance: versioning, quality validation, train/val/test isolation, and auditability.',
            'Model Registry & Versioning: artifact registry, metadata tracking, feature transformer compatibility, and deployment history.',
            'Model Performance Monitoring: per-attack-family metrics, FPR/FNR trends, concept drift, and confidence calibration.',
            'Controlled Retraining: trigger policies, regression testing against baselines, rare attack checks, and human sign-off.',
            'Deployment & Recovery: versioned model rollouts, canary/staged deployment, automated rollback, and reproducible restoration.'
          ],
        },
        {
          letter: 'C',
          title: 'Alert Intelligence & Prioritisation',
          category: 'Triage & Scoring',
          icon: BellRing,
          status: 'Implemented (Partial Baseline)',
          badgeClass: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
          currentVerified: 'P3 five-factor class-aware composite scoring with dynamic Critical/Review/Auto-log tiers and unknown-service Review floor.',
          missingWork: 'Cross-sensor correlation, temporal deduplication, incident-level scoring, CMDB integration, and alert lifecycle state management.',
          targetStage: 'Stage 2 & Stage 3',
          dependencies: 'Persistent alert index, CMDB API bindings',
          acceptanceSummary: '≥ 60% alert noise reduction into correlated incidents; 100% triage audit trail',
          scope: [
            'Class-aware composite risk scoring balancing confidence, anomaly, severity, and asset impact (Validated in P3).',
            'Asset criticality assessment with documented unknown-service Review floor (Validated in P3).',
            'Cross-sensor alert correlation clustering related events across network sensors and endpoints.',
            'Temporal deduplication clustering repeated events from identical host pairs into unified alerts.',
            'Incident-level risk aggregation combining multi-stage alert scores into campaign severity.',
            'Context-sensitive false-positive reduction based on historical baseline suppressions.',
            'Asset inventory and CMDB integration (ServiceNow, Device42) for dynamic asset value synchronization.',
            'Comprehensive alert lifecycle management (state machine: New → Triage → Investigating → Resolved → Closed).',
            'SLA tracking, auto-assignment, and analyst workload distribution.',
            'Priority score explainability decomposing the contributing terms for transparent auditability.',
            'Analyst feedback loops and interactive triage tuning to adapt scoring to organizational risk tolerance.'
          ],
        }
      ]
    },
    {
      clusterName: 'Incident Investigation & Response',
      clusterDesc: 'SOC workbench, forensic binders, playbooks, and SOAR handoffs',
      color: 'cyan',
      modules: [
        {
          letter: 'D',
          title: 'Investigation & Incident Management',
          category: 'SOC Workflows',
          icon: FileText,
          status: 'Planned Engineering',
          badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
          currentVerified: 'Incident triage priority queue, alert replay inspector, and SHAP feature explainability.',
          missingWork: 'Incident entity grouping, interactive attack timelines, evidence binders, MITRE ATT&CK mapping, and compliance reports.',
          targetStage: 'Stage 3 & Stage 4',
          dependencies: 'Correlated incident store, MITRE ATT&CK STIX ontology',
          acceptanceSummary: 'Kill-chain visualization; exportable NIST CSF / ISO audit reports',
          scope: [
            'Automated incident creation, multi-alert grouping, severity scoping, and owner assignment.',
            'Multi-alert investigation consoles enabling cross-sensor pivoting and correlation.',
            'Interactive attack timelines tracing events chronologically across the cyber kill chain.',
            'Comprehensive MITRE ATT&CK enterprise technique mapping and coverage heatmaps.',
            'Cryptographic evidence collection, raw flow artifact capture, and chain-of-custody verification.',
            'Collaborative investigation notes, analyst scratchpads, and shared investigation workspaces.',
            'Audit-ready incident and compliance reporting (NIST CSF, ISO 27001, SOC 2, HIPAA).',
            'Threat intelligence context linking internal incident indicators to external adversary campaigns.',
            'Investigation history and immutable analyst audit trails recording all forensic actions.'
          ],
        },
        {
          letter: 'E',
          title: 'Response & Security Automation',
          category: 'Orchestration & Response',
          icon: Workflow,
          status: 'Planned Engineering',
          badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
          currentVerified: 'Triage tier recommendations, lab simulation controls, and priority queue sorting.',
          missingWork: 'Automated response playbooks, ticketing dispatch, SOAR connectors, and forensic artifact capture.',
          targetStage: 'Stage 3 & Stage 4',
          dependencies: 'Ticketing REST APIs, SOAR webhook connectors',
          acceptanceSummary: 'Zero autonomous destructive actions; 100% analyst sign-off compliance',
          scope: [
            'Contextual response recommendations per threat family, asset criticality, and alert tier.',
            'Configurable visual response playbooks for containment, artifact gathering, and mitigation.',
            'Analyst-approved response workflows: mandatory human authorization for active containment actions.',
            'Strict guardrails: No autonomous blocking or disruptive actions without explicit analyst sign-off.',
            'Enterprise ticketing integrations (ServiceNow, Jira Service Management, PagerDuty, Slack, Teams).',
            'Enterprise SOAR bi-directional handoff (Cortex XSOAR, Splunk SOAR, Swimlane).',
            'Automated forensic collection workflows (host memory capture, process tree extraction, netstat snapshot).',
            'Response execution history and containment audit trails recording authorization and execution status.'
          ],
        }
      ]
    },
    {
      clusterName: 'Platform Governance & Strategic Horizons',
      clusterDesc: 'Multi-tenant trust, assistive AI intelligence, and commercial UX',
      color: 'purple',
      modules: [
        {
          letter: 'F',
          title: 'Enterprise Management & SaaS Governance',
          category: 'Foundational SaaS Requirements & Tenant Trust',
          icon: ShieldCheck,
          status: 'Planned Engineering (Foundational Requirement)',
          badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
          currentVerified: 'System health liveness probe, database connection status telemetry, and offline fallback mode.',
          missingWork: 'Multi-tenant architecture, 10 cryptographic isolation boundaries, automated negative authorization tests, RBAC, SSO/MFA, API quotas, and audit logging.',
          targetStage: 'Stage 1 & Stage 4',
          dependencies: 'Identity provider (OIDC/SAML), Vault KMS, cloud IaC',
          acceptanceSummary: '99.9% availability; verified zero cross-tenant leakage; RTO ≤ 15m / RPO ≤ 5m',
          scope: [
            'Multi-tenant architecture designed from the ground up prior to onboarding external customers.',
            'Ten Security Boundaries: Database-level isolation, object storage isolation, cache & queue isolation, API context authorization, background job isolation, model dataset & artifact isolation, log/export/backup isolation, administrative RBAC, secrets management, and tenant auditability.',
            'Automated negative security testing verifying cross-tenant access denial across IDOR, API endpoints, background jobs, exports, admin functions, and model retrieval.',
            'Organisation and workspace management for MSSPs, business units, and distributed SOC teams.',
            'Authentication and secure session management with token rotation and inactivity timeouts.',
            'Fine-grained Role-Based Access Control (RBAC: Viewer, Analyst, Lead, Admin) and permission boundaries.',
            'Enterprise Single Sign-On (SSO via SAML 2.0 / OIDC) and mandatory Multi-Factor Authentication (MFA).',
            'Scoped API keys, programmatic access management, rate limiting, and tenant usage quotas.',
            'Immutable, tamper-evident audit logging recording user logins, triage decisions, and model changes.',
            'Tenant-specific detection configuration, policy overrides, and custom suppression rules.',
            'Secure data retention policies, automated cold archival, and cryptographic data deletion.',
            'Model and detection-rule versioning tracking lineages, training sets, and canary deployment gates.',
            'Enterprise secrets management (HashiCorp Vault / envelope encryption).',
            'Operational resilience: distributed high availability (HA), automated backups, and disaster recovery (DR).',
            'Platform health monitoring, operational observability, and administrative controls.'
          ],
        },
        {
          letter: 'G',
          title: 'Future AI-Powered Capabilities',
          category: 'Governed AI & Assistive Analytics',
          icon: Bot,
          status: 'Long-Term Exploratory Vision',
          badgeClass: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30',
          currentVerified: 'SHAP tree feature attribution and per-feature reconstruction error decomposition.',
          missingWork: 'LLM security assistant, natural-language query parsing, automated summaries, and AI safety guardrails.',
          targetStage: 'Stage 5 (Optional Parallel Workstream)',
          dependencies: 'Enterprise RBAC, contextual incident data store, LLM gateway',
          acceptanceSummary: '≥ 99% prompt-injection defense rate; ≥ 35% MTTU reduction; 100% human sign-off',
          scope: [
            'Conversational AI Security Analyst Assistant providing natural-language incident explanations and guidance.',
            'Natural-language threat investigation converting analyst questions into structured queries (Text-to-SQL/ES).',
            'Automated incident summarisation generating executive handoff reports and post-incident reviews.',
            'Shift handoff reports synthesizing multi-analyst investigations and outstanding triage queues.',
            'AI-assisted detection rule drafting: synthesizing Sigma/YARA-L rules from threat intelligence advisories.',
            'Evidence-grounded investigation assistance: no authoritative conclusions without verifiable evidence.',
            'Supervised agentic investigation workflows gathering evidence autonomously under strict human approval.',
            'Mandatory human sign-off for any consequential or active containment actions recommended by AI.',
            'Prompt-injection protection and adversarial input sanitization layers (≥ 99% mitigation benchmark target).',
            'Retrieval-Augmented Generation (RAG) grounding and hallucination controls bounded by tenant data.',
            'Immutable AI activity audit trails recording all prompts, generated outputs, and analyst approval states.'
          ],
        },
        {
          letter: 'H',
          title: 'Future Product Experience',
          category: 'UI/UX & Operational Visualization',
          icon: LayoutDashboard,
          status: 'Long-Term Exploratory Vision',
          badgeClass: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
          currentVerified: 'React + Vite + Tailwind SOC dashboard v2.4 (Executive Hub, Overview, Triage Queue, Labs, Model Intel).',
          missingWork: 'Tenant-specific dashboards, modular customizable layouts, streaming charts, and interactive attack graphs.',
          targetStage: 'Stage 6 (Commercial Validation)',
          dependencies: 'Stage 4 multi-tenancy, Stage 3 streaming pipelines, Stage 2 detection models',
          acceptanceSummary: '≥ 3 authorized pilot deployments; ≥ 40% reduction in triage time; NPS ≥ 50',
          scope: [
            'Enterprise-grade SOC user experience redesign optimized for multi-monitor operations centers.',
            'Tenant-specific and role-tailored dashboard views for executives, tier-1 analysts, and incident responders.',
            'Fully customizable dashboards with drag-and-drop KPI widgets and analyst layout presets.',
            'Real-time streaming telemetry monitoring with dynamic queue throughput counters and live indicators.',
            'Dedicated incident workspaces integrating attack chronologies, evidence binders, and team scratchpads.',
            'Interactive attack graphs rendering node-link topology and multi-hop attack campaigns.',
            'Unified forensics workbench integrating raw packet dissection with SHAP feature explainability.',
            'Model performance dashboards tracking live accuracy, recall, and concept drift over time.',
            'Executive security posture reporting tracking MTTD, MTTR, and alert fatigue reduction metrics.',
            'Organisation-level usage, quota consumption, and platform health telemetry dashboards.'
          ],
        }
      ]
    }
  ]

  const allModulesList = moduleClusters.flatMap(c => c.modules)
  const activeSelectedStage = developmentStages[selectedStageIndex]
  const activeSelectedProblem = foundationalProblems.find(p => p.id === selectedProblemId)
  const activeSelectedModule = allModulesList.find(m => m.letter === selectedModuleLetter)
  const activeSelectedWorkstream = dependencyWorkstreams.find(w => w.id === selectedWorkstreamId)

  // Filter dependency nodes
  const filteredWorkstreams = dependencyFilter === 'all'
    ? dependencyWorkstreams
    : dependencyWorkstreams.filter(w => w.milestone === dependencyFilter)

  return (
    <div className="space-y-8 animate-fade-in max-w-7xl mx-auto pb-20">
      {/* --------------------------------------------------------------------- */}
      {/* A. Strategic Overview Header                                           */}
      {/* --------------------------------------------------------------------- */}
      <div className="space-y-4 border-b border-white/8 pb-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-2">
              <span className="text-[10px] font-mono uppercase tracking-widest px-2.5 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                AEGIS Strategic Roadmap
              </span>
              <span className="text-xs font-mono text-slate-400">Platform Vision & Phased Execution</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white flex items-center gap-3">
              Intelligent Cybersecurity Operations Platform
            </h1>
            <p className="text-xs sm:text-sm text-slate-300 mt-1 max-w-3xl leading-relaxed">
              An extensible SecOps platform evolving from verified ML anomaly and encryption detection into an enterprise multi-tenant threat management SaaS.
            </p>
          </div>

          <div className="flex items-center gap-2.5 shrink-0">
            <Link
              to="/overview"
              className="text-xs font-mono px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10 transition-colors flex items-center gap-1.5"
            >
              <span>Live Overview</span>
              <ArrowRight size={13} />
            </Link>
          </div>
        </div>

        {/* Development Position Ribbon */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 p-3 rounded-xl bg-slate-900/60 border border-white/10 text-xs">
          <div className="flex items-center gap-2.5">
            <div className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse shrink-0" />
            <div>
              <span className="text-[10px] font-mono text-slate-400 uppercase block">Current Position</span>
              <span className="font-semibold text-white">Stage 1 & 2 Transition</span>
            </div>
          </div>
          <div>
            <span className="text-[10px] font-mono text-slate-400 uppercase block">Research Bedrock</span>
            <span className="font-semibold text-emerald-400">4 Validated Problems</span>
          </div>
          <div>
            <span className="text-[10px] font-mono text-slate-400 uppercase block">SaaS Modules</span>
            <span className="font-semibold text-cyan-400">8 Functional Domains (A–H)</span>
          </div>
          <div>
            <span className="text-[10px] font-mono text-slate-400 uppercase block">Execution Horizon</span>
            <span className="font-semibold text-indigo-400">6 Phased Milestones</span>
          </div>
        </div>

        {/* Compact Status Taxonomy Legend & Navigation Tabs */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pt-2">
          {/* Status Taxonomy */}
          <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-mono text-slate-400">
            <span className="text-[10px] uppercase text-slate-400 mr-1">Status Legend:</span>
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              Validated Baseline
            </span>
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
              In Progress / Partial
            </span>
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-amber-500/10 text-amber-400 border border-amber-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
              Planned Engineering
            </span>
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-indigo-400" />
              Long-Term Vision
            </span>
          </div>

          {/* Four Primary Section Navigation Tabs */}
          <div className="inline-flex p-1 rounded-xl bg-slate-900 border border-white/10 shrink-0">
            <button
              onClick={() => setActiveSection('roadmap')}
              className={`px-3 py-1 rounded-lg text-xs font-mono font-medium transition-all flex items-center gap-1.5 ${
                activeSection === 'roadmap'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Milestone size={13} />
              <span>Stages (1–6)</span>
            </button>
            <button
              onClick={() => setActiveSection('dependencies')}
              className={`px-3 py-1 rounded-lg text-xs font-mono font-medium transition-all flex items-center gap-1.5 ${
                activeSection === 'dependencies'
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <GitBranch size={13} />
              <span>Dependencies</span>
            </button>
            <button
              onClick={() => setActiveSection('ecosystem')}
              className={`px-3 py-1 rounded-lg text-xs font-mono font-medium transition-all flex items-center gap-1.5 ${
                activeSection === 'ecosystem'
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Network size={13} />
              <span>Modules (A–H)</span>
            </button>
            <button
              onClick={() => setActiveSection('governance')}
              className={`px-3 py-1 rounded-lg text-xs font-mono font-medium transition-all flex items-center gap-1.5 ${
                activeSection === 'governance'
                  ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Shield size={13} />
              <span>Governance & Matrix</span>
            </button>
          </div>
        </div>
      </div>

      {/* --------------------------------------------------------------------- */}
      {/* B. Research Bedrock: Validated Problems (P1 to P4)                    */}
      {/* --------------------------------------------------------------------- */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-400">Validated Bedrock</span>
            <span className="text-slate-600">·</span>
            <span className="text-xs font-mono text-slate-400">Four Foundational Research Engines</span>
          </div>
          <span className="text-[11px] font-mono text-slate-400 hidden sm:inline">
            Click any problem card to inspect verifiable metrics & limitations
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {foundationalProblems.map((p) => {
            const Icon = p.icon
            const isSelected = selectedProblemId === p.id
            return (
              <div
                key={p.id}
                onClick={() => setSelectedProblemId(isSelected ? null : p.id)}
                className={`group p-4 rounded-xl border transition-all cursor-pointer flex flex-col justify-between relative overflow-hidden ${
                  isSelected
                    ? 'bg-slate-900 border-emerald-500/60 shadow-lg shadow-emerald-500/10'
                    : 'bg-slate-900/50 border-white/10 hover:border-emerald-500/30 hover:bg-slate-900/80'
                }`}
              >
                <div className="space-y-2.5">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 group-hover:scale-105 transition-transform">
                        <Icon size={16} />
                      </div>
                      <div>
                        <span className="text-[10px] font-mono font-bold text-emerald-400">{p.id}</span>
                        <h3 className="text-xs font-bold text-white leading-tight">{p.shortTitle}</h3>
                      </div>
                    </div>
                    <span className="text-[9px] font-mono px-2 py-0.5 rounded-full border bg-emerald-500/10 text-emerald-300 border-emerald-500/20 shrink-0">
                      Validated
                    </span>
                  </div>

                  <p className="text-[11px] text-slate-300 leading-snug font-sans line-clamp-2">
                    {p.tagline}
                  </p>

                  {/* Compact Metrics Row */}
                  <div className="grid grid-cols-2 gap-1.5 pt-1">
                    <div className="p-1.5 rounded-lg bg-black/40 border border-white/5">
                      <span className="text-[9px] font-mono text-slate-400 block truncate">{p.heroMetric.label}</span>
                      <span className="text-xs font-mono font-bold text-emerald-400">{p.heroMetric.val}</span>
                    </div>
                    <div className="p-1.5 rounded-lg bg-black/40 border border-white/5">
                      <span className="text-[9px] font-mono text-slate-400 block truncate">{p.secondaryMetric.label}</span>
                      <span className="text-xs font-mono font-bold text-slate-200">{p.secondaryMetric.val}</span>
                    </div>
                  </div>
                </div>

                <div className="mt-3 pt-2.5 border-t border-white/5 flex items-center justify-between text-[10px] font-mono">
                  <span className="text-cyan-400 group-hover:underline flex items-center gap-1">
                    <span>{isSelected ? 'Close Details' : 'View Details'}</span>
                    <ChevronDown size={11} className={`transition-transform duration-200 ${isSelected ? 'rotate-180' : ''}`} />
                  </span>
                  <Link
                    to={p.link}
                    onClick={(e) => e.stopPropagation()}
                    className="text-slate-400 hover:text-white flex items-center gap-0.5"
                    title={p.linkLabel}
                  >
                    <span>Lab</span>
                    <ArrowRight size={10} />
                  </Link>
                </div>
              </div>
            )
          })}
        </div>

        {/* Expanded Problem Detail Drawer */}
        {activeSelectedProblem && (
          <div className="p-5 rounded-2xl bg-slate-900 border border-emerald-500/30 space-y-4 shadow-xl animate-fade-in relative">
            <button
              onClick={() => setSelectedProblemId(null)}
              className="absolute top-4 right-4 p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white transition-colors"
            >
              <X size={16} />
            </button>

            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-3 pr-8">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <activeSelectedProblem.icon size={22} />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-emerald-400">{activeSelectedProblem.id}</span>
                    <span className="text-slate-600">·</span>
                    <span className="text-xs font-mono text-slate-400">{activeSelectedProblem.subtitle}</span>
                  </div>
                  <h3 className="text-lg font-bold text-white">{activeSelectedProblem.title}</h3>
                </div>
              </div>

              <Link
                to={activeSelectedProblem.link}
                className="text-xs font-mono px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 transition-colors flex items-center gap-1.5 self-start sm:self-auto"
              >
                <span>{activeSelectedProblem.linkLabel}</span>
                <ExternalLink size={12} />
              </Link>
            </div>

            <p className="text-xs text-slate-200 leading-relaxed font-sans">
              {activeSelectedProblem.body}
            </p>

            {/* Verified Metrics Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              {activeSelectedProblem.metrics.map((m, i) => (
                <div key={i} className="p-3 rounded-xl bg-black/40 border border-white/5 space-y-1">
                  <span className="text-[10px] font-mono text-slate-400 block">{m.label}</span>
                  <span className="text-sm font-mono font-bold text-emerald-400 block">{m.val}</span>
                  <span className="text-[10px] text-slate-400 font-sans leading-tight block">{m.sub}</span>
                </div>
              ))}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              {/* Architecture Details */}
              <div className="p-3 rounded-xl bg-slate-950/60 border border-white/5 space-y-1">
                <div className="flex items-center gap-1.5 text-cyan-300 font-mono text-[11px] font-semibold">
                  <Info size={13} />
                  <span>Architecture & Mathematical Foundation</span>
                </div>
                <p className="text-slate-300 font-sans text-[11px] leading-relaxed">
                  {activeSelectedProblem.architectureNote}
                </p>
              </div>

              {/* Scope Boundary */}
              {activeSelectedProblem.scopeLimitation && (
                <div className="p-3 rounded-xl bg-amber-950/20 border border-amber-500/20 space-y-1">
                  <div className="flex items-center gap-1.5 text-amber-300 font-mono text-[11px] font-semibold">
                    <AlertTriangle size={13} />
                    <span>Scope Boundary & Known Limitations</span>
                  </div>
                  <p className="text-amber-200/90 font-sans text-[11px] leading-relaxed">
                    {activeSelectedProblem.scopeLimitation}
                  </p>
                </div>
              )}
            </div>

            {/* Future Research Directions */}
            <div className="space-y-2 pt-2 border-t border-white/5">
              <span className="text-xs font-mono uppercase tracking-wider text-purple-300 font-semibold block">
                Planned Future Research Extensions
              </span>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-slate-300 font-sans">
                {activeSelectedProblem.futureResearch.map((item, idx) => (
                  <div key={idx} className="flex items-start gap-1.5 leading-snug">
                    <ChevronRight size={13} className="text-purple-400 shrink-0 mt-0.5" />
                    <span className="text-[11px]">{item}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </section>

      {/* --------------------------------------------------------------------- */}
      {/* C. The Visual Centerpiece: Main Six-Stage Strategic Roadmap            */}
      {/* --------------------------------------------------------------------- */}
      {activeSection === 'roadmap' && (
        <section className="space-y-6 pt-2">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/5 pb-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400">Execution Lifecycle</span>
                <span className="text-slate-600">·</span>
                <span className="text-xs font-mono text-slate-400">Sequential Development Progression</span>
              </div>
              <h2 className="text-lg font-bold text-white">
                The AEGIS Six-Stage Development Journey
              </h2>
            </div>
            <span className="text-xs font-mono text-slate-400">
              Select any stage to inspect objectives, acceptance criteria & dependencies
            </span>
          </div>

          {/* Desktop Interactive Horizontal Connected Progression */}
          <div className="hidden lg:grid grid-cols-6 gap-2 relative pt-2">
            {/* Visual Connected Baseline Bar */}
            <div className="absolute top-7 left-8 right-8 h-0.5 bg-slate-800 -z-0" />
            <div className="absolute top-7 left-8 w-[25%] h-0.5 bg-gradient-to-r from-cyan-500 to-emerald-400 -z-0" />

            {developmentStages.map((s, idx) => {
              const isSelected = selectedStageIndex === idx
              const isCurrent = idx === 1 // Stage 2
              const isCompletedOrActive = idx <= 1
              return (
                <div
                  key={s.stage}
                  onClick={() => setSelectedStageIndex(idx)}
                  className={`p-3 rounded-xl border transition-all cursor-pointer flex flex-col justify-between relative z-10 ${
                    isSelected
                      ? 'bg-slate-900 border-cyan-400 shadow-lg shadow-cyan-500/10 -translate-y-1'
                      : 'bg-slate-900/60 border-white/10 hover:border-white/30 hover:bg-slate-900/90'
                  }`}
                >
                  <div className="space-y-2">
                    {/* Stage Step Node */}
                    <div className="flex items-center justify-between">
                      <div
                        className={`w-8 h-8 rounded-full flex items-center justify-center font-mono text-xs font-bold border transition-colors ${
                          isSelected
                            ? 'bg-cyan-500 text-black border-cyan-300 shadow-md shadow-cyan-500/30'
                            : isCurrent
                            ? 'bg-emerald-500/20 text-emerald-300 border-emerald-400'
                            : isCompletedOrActive
                            ? 'bg-cyan-950 text-cyan-300 border-cyan-500/40'
                            : 'bg-slate-900 text-slate-400 border-slate-700'
                        }`}
                      >
                        {s.stageNumber}
                      </div>

                      <span
                        className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${
                          isCurrent
                            ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30 animate-pulse'
                            : s.status.includes('Vision')
                            ? 'bg-indigo-500/10 text-indigo-300 border-indigo-500/20'
                            : 'bg-white/5 text-slate-400 border-white/10'
                        }`}
                      >
                        {isCurrent ? 'Current' : s.status.includes('Progress') ? 'Active' : s.status.includes('Vision') ? 'Vision' : 'Planned'}
                      </span>
                    </div>

                    <div>
                      <h4 className="text-xs font-bold text-white leading-snug line-clamp-2">{s.title}</h4>
                      <p className="text-[10px] text-slate-400 font-sans mt-1 leading-tight line-clamp-2">{s.oneLiner}</p>
                    </div>

                    {/* Quick Focus Tags */}
                    <div className="flex flex-wrap gap-1 pt-1">
                      {s.focusAreas.slice(0, 2).map((fa, i) => (
                        <span key={i} className="text-[9px] font-mono px-1 py-0.5 rounded bg-black/40 text-slate-300 truncate max-w-full">
                          {fa}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="mt-3 pt-2 border-t border-white/5 text-[10px] font-mono text-center">
                    <span className={isSelected ? 'text-cyan-400 font-bold' : 'text-slate-400'}>
                      {isSelected ? '● Selected' : 'Click to inspect'}
                    </span>
                  </div>
                </div>
              )
            })}
          </div>

          {/* Mobile/Tablet Connected Vertical Progression */}
          <div className="lg:hidden space-y-3">
            {developmentStages.map((s, idx) => {
              const isSelected = selectedStageIndex === idx
              const isCurrent = idx === 1
              return (
                <div
                  key={s.stage}
                  onClick={() => setSelectedStageIndex(idx)}
                  className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                    isSelected
                      ? 'bg-slate-900 border-cyan-400 shadow-md'
                      : 'bg-slate-900/60 border-white/10'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2.5">
                      <div className={`w-7 h-7 rounded-full flex items-center justify-center font-mono text-xs font-bold border ${
                        isSelected
                          ? 'bg-cyan-500 text-black border-cyan-300'
                          : isCurrent
                          ? 'bg-emerald-500/20 text-emerald-300 border-emerald-400'
                          : 'bg-slate-800 text-slate-300 border-slate-700'
                      }`}>
                        {s.stageNumber}
                      </div>
                      <div>
                        <span className="text-xs font-bold text-white block">{s.stage}: {s.title}</span>
                        <span className="text-[10px] text-slate-400">{s.oneLiner}</span>
                      </div>
                    </div>
                    <span className={`text-[9px] font-mono px-2 py-0.5 rounded-full border shrink-0 ${s.badgeClass}`}>
                      {s.status}
                    </span>
                  </div>
                </div>
              )
            })}
          </div>

          {/* Active Stage Detailed Panel (Compact Two-Column Architecture) */}
          {activeSelectedStage && (
            <div className="p-6 rounded-2xl bg-gradient-to-br from-slate-900 via-slate-900/90 to-black border border-cyan-500/30 space-y-5 shadow-xl animate-fade-in">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center font-mono font-bold text-base">
                    {activeSelectedStage.stageNumber}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold text-cyan-400">{activeSelectedStage.stage}</span>
                      <span className="text-slate-600">·</span>
                      <span className="text-xs font-mono text-slate-400">Execution Phase</span>
                    </div>
                    <h3 className="text-lg font-bold text-white">{activeSelectedStage.title}</h3>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setExpandStageContent(!expandStageContent)}
                    className="text-[11px] font-mono px-2.5 py-1 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10 transition-colors flex items-center gap-1"
                  >
                    <span>{expandStageContent ? 'Compact View' : 'Show Full Scope'}</span>
                    <ChevronDown size={12} className={`transition-transform duration-200 ${expandStageContent ? 'rotate-180' : ''}`} />
                  </button>
                  <span className={`text-[11px] font-mono px-3 py-1 rounded-full border self-start sm:self-auto ${activeSelectedStage.badgeClass}`}>
                    {activeSelectedStage.status}
                  </span>
                </div>
              </div>

              <p className="text-xs text-slate-200 leading-relaxed font-sans">
                {activeSelectedStage.summary}
              </p>

              <div className="grid md:grid-cols-2 gap-6 pt-1">
                {/* Left Column: Objectives, Deliverables & Workstreams */}
                <div className="space-y-4">
                  <div className="space-y-2">
                    <span className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider block">
                      Core Engineering Deliverables
                    </span>
                    <ul className="space-y-2 text-xs text-slate-300">
                      {(expandStageContent ? activeSelectedStage.objectives : activeSelectedStage.objectives.slice(0, 4)).map((obj, i) => (
                        <li key={i} className="flex items-start gap-2 font-sans leading-snug">
                          <ChevronRight size={13} className="text-cyan-400 shrink-0 mt-0.5" />
                          <span>{obj}</span>
                        </li>
                      ))}
                    </ul>
                    {!expandStageContent && activeSelectedStage.objectives.length > 4 && (
                      <span className="text-[10px] font-mono text-cyan-400/80 pl-5 block">
                        + {activeSelectedStage.objectives.length - 4} additional deliverables (toggle Show Full Scope above)
                      </span>
                    )}
                  </div>

                  {/* Workstreams involved */}
                  <div className="p-3 rounded-xl bg-black/40 border border-white/5 space-y-1.5 text-xs">
                    <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-wider font-semibold block">
                      Associated Engineering Workstreams
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {activeSelectedStage.workstreams.map((ws, i) => (
                        <span key={i} className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/40 text-cyan-300 border border-cyan-500/20">
                          {ws}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Right Column: Measurable Acceptance Criteria, Dependencies & Exit Prerequisites */}
                <div className="space-y-4">
                  <div className="space-y-2">
                    <span className="text-xs font-mono font-bold text-emerald-300 uppercase tracking-wider block">
                      Measurable Acceptance Criteria
                    </span>
                    <ul className="space-y-2 text-xs text-slate-300">
                      {activeSelectedStage.acceptanceCriteria.map((crit, i) => (
                        <li key={i} className="flex items-start gap-2 font-sans leading-snug">
                          <CheckCircle2 size={13} className="text-emerald-400 shrink-0 mt-0.5" />
                          <span>{crit}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="p-3.5 rounded-xl bg-black/50 border border-white/5 space-y-2 text-xs">
                    <div>
                      <span className="font-mono text-slate-400 text-[10px] uppercase block">Dependencies</span>
                      <span className="text-slate-300 font-sans text-[11px]">{activeSelectedStage.dependencies}</span>
                    </div>
                    <div className="border-t border-white/5 pt-2">
                      <span className="font-mono text-cyan-400 text-[10px] uppercase block">Stage Exit Prerequisite</span>
                      <span className="text-cyan-200/90 font-sans text-[11px]">{activeSelectedStage.prerequisite}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </section>
      )}

      {/* --------------------------------------------------------------------- */}
      {/* 4. Dedicated Interactive Dependency View (Reconciled Phase 2A Backlog) */}
      {/* --------------------------------------------------------------------- */}
      {activeSection === 'dependencies' && (
        <section className="space-y-6 pt-2">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/5 pb-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-400">Engineering Backlog Graph</span>
                <span className="text-slate-600">·</span>
                <span className="text-xs font-mono text-slate-400">Reconciled Phase 2A Dependency Map</span>
              </div>
              <h2 className="text-lg font-bold text-white">
                Workstream Relationships & Critical Path Execution
              </h2>
            </div>

            {/* Milestone Filter Pills */}
            <div className="flex items-center gap-1 p-1 rounded-xl bg-slate-900 border border-white/10 text-xs font-mono shrink-0">
              <Filter size={12} className="text-slate-400 ml-1.5 mr-0.5" />
              {(['all', 'M1', 'M2', 'M3', 'M4'] as const).map((m) => (
                <button
                  key={m}
                  onClick={() => setDependencyFilter(m)}
                  className={`px-2.5 py-1 rounded-lg transition-colors uppercase ${
                    dependencyFilter === m
                      ? 'bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/30'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {m === 'all' ? 'All Phases' : m}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            {/* Left 7 Columns: Workstream Node Grid */}
            <div className="lg:col-span-7 space-y-3">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400 pb-1">
                <span>Select a workstream node to inspect upstream & downstream links:</span>
                <span>{filteredWorkstreams.length} Workstreams</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                {filteredWorkstreams.map((ws) => {
                  const isSelected = selectedWorkstreamId === ws.id
                  return (
                    <div
                      key={ws.id}
                      onClick={() => setSelectedWorkstreamId(ws.id)}
                      className={`p-3 rounded-xl border transition-all cursor-pointer flex flex-col justify-between ${
                        isSelected
                          ? 'bg-slate-900 border-emerald-400 shadow-md shadow-emerald-500/10 -translate-y-0.5'
                          : 'bg-slate-900/50 border-white/10 hover:border-emerald-500/30 hover:bg-slate-900/80'
                      }`}
                    >
                      <div className="space-y-2">
                        <div className="flex items-center justify-between gap-1">
                          <div className="flex items-center gap-1.5">
                            <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-black/50 text-cyan-400 border border-white/10">
                              {ws.milestone}
                            </span>
                            <span className="text-[10px] font-mono text-slate-400">{ws.code}</span>
                          </div>
                          <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded-full border ${ws.badgeClass}`}>
                            {ws.status}
                          </span>
                        </div>

                        <div>
                          <h4 className="text-xs font-bold text-white leading-snug line-clamp-1">{ws.name}</h4>
                          <span className="text-[10px] text-slate-400 font-sans block">{ws.category}</span>
                        </div>

                        {/* Task Count & Unblocks Indicator */}
                        <div className="flex items-center justify-between text-[10px] font-mono pt-1 text-slate-400">
                          <span>{ws.tasks.length} Backlog Tasks</span>
                          {ws.unblocks.length > 0 ? (
                            <span className="text-emerald-400 flex items-center gap-0.5">
                              <span>Unblocks {ws.unblocks.length}</span>
                              <ArrowUpRight size={11} />
                            </span>
                          ) : (
                            <span className="text-slate-500">Terminal Node</span>
                          )}
                        </div>
                      </div>

                      <div className="mt-2.5 pt-2 border-t border-white/5 flex items-center justify-between text-[10px] font-mono">
                        <span className="text-slate-500 truncate max-w-[120px]">
                          {ws.prerequisites.length === 0 ? 'Foundation (No Pre-reqs)' : `Pre-req: ${ws.prerequisites.join(', ')}`}
                        </span>
                        <span className={isSelected ? 'text-emerald-400 font-bold' : 'text-slate-400'}>
                          {isSelected ? '● Inspected' : 'Inspect'}
                        </span>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Right 5 Columns: Workstream Inspector Detail Card */}
            <div className="lg:col-span-5">
              {activeSelectedWorkstream ? (
                <div className="p-5 rounded-2xl bg-slate-900 border border-emerald-500/30 space-y-4 shadow-xl sticky top-20">
                  <div className="border-b border-white/10 pb-3">
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-bold text-emerald-400">{activeSelectedWorkstream.id}</span>
                        <span className="text-slate-600">·</span>
                        <span className="text-xs font-mono text-slate-400">{activeSelectedWorkstream.milestoneTitle}</span>
                      </div>
                      <span className={`text-[9px] font-mono px-2 py-0.5 rounded-full border ${activeSelectedWorkstream.badgeClass}`}>
                        {activeSelectedWorkstream.status}
                      </span>
                    </div>
                    <h3 className="text-base font-bold text-white">{activeSelectedWorkstream.name}</h3>
                    <p className="text-xs text-slate-300 font-sans mt-1 leading-snug">{activeSelectedWorkstream.description}</p>
                  </div>

                  {/* Tasks List */}
                  <div className="space-y-1.5">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold block">
                      Consolidated Backlog Tasks ({activeSelectedWorkstream.tasks.length})
                    </span>
                    <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
                      {activeSelectedWorkstream.tasks.map((t) => (
                        <div key={t.id} className="p-2 rounded-lg bg-black/40 border border-white/5 flex items-start justify-between gap-2 text-xs">
                          <div className="flex items-start gap-1.5 font-sans leading-tight">
                            <span className="text-cyan-400 font-mono font-bold text-[11px] shrink-0">{t.id}:</span>
                            <span className="text-slate-200 text-[11px]">{t.name}</span>
                          </div>
                          <div className="flex items-center gap-1 shrink-0 font-mono text-[9px]">
                            <span className="px-1.5 py-0.5 rounded bg-white/5 text-amber-300 border border-white/5">{t.priority}</span>
                            {t.cvss && <span className="px-1.5 py-0.5 rounded bg-rose-950/40 text-rose-300 border border-rose-500/20">CVSS {t.cvss}</span>}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Upstream & Downstream Relationship Diagram */}
                  <div className="grid grid-cols-2 gap-2 text-xs font-mono pt-1">
                    <div className="p-2.5 rounded-xl bg-black/40 border border-white/5 space-y-1">
                      <span className="text-[10px] text-slate-400 block uppercase">Requires Upstream:</span>
                      {activeSelectedWorkstream.prerequisites.length > 0 ? (
                        <div className="space-y-1">
                          {activeSelectedWorkstream.prerequisites.map((pId) => (
                            <button
                              key={pId}
                              onClick={() => setSelectedWorkstreamId(pId)}
                              className="text-[11px] text-cyan-300 hover:underline block text-left truncate w-full"
                            >
                              ← {pId}
                            </button>
                          ))}
                        </div>
                      ) : (
                        <span className="text-[11px] text-emerald-400 flex items-center gap-1 font-sans">
                          <Check size={12} /> Ground-level Foundation
                        </span>
                      )}
                    </div>

                    <div className="p-2.5 rounded-xl bg-black/40 border border-white/5 space-y-1">
                      <span className="text-[10px] text-slate-400 block uppercase">Unblocks Downstream:</span>
                      {activeSelectedWorkstream.unblocks.length > 0 ? (
                        <div className="space-y-1">
                          {activeSelectedWorkstream.unblocks.map((uId) => (
                            <button
                              key={uId}
                              onClick={() => setSelectedWorkstreamId(uId)}
                              className="text-[11px] text-emerald-300 hover:underline block text-left truncate w-full"
                            >
                              → {uId}
                            </button>
                          ))}
                        </div>
                      ) : (
                        <span className="text-[11px] text-slate-400 font-sans">Terminal execution node</span>
                      )}
                    </div>
                  </div>

                  {/* Risk & Acceptance Criteria */}
                  <div className="space-y-2 text-xs pt-1 border-t border-white/5">
                    <div className="p-2.5 rounded-xl bg-amber-950/20 border border-amber-500/20 space-y-0.5">
                      <span className="text-[10px] font-mono text-amber-400 font-semibold block uppercase">Known Risk & Mitigation</span>
                      <p className="text-[11px] text-amber-200/90 font-sans leading-snug">{activeSelectedWorkstream.risk}</p>
                    </div>

                    <div className="space-y-1">
                      <span className="text-[10px] font-mono text-emerald-400 font-semibold uppercase block">Acceptance Criteria</span>
                      <ul className="space-y-1 text-slate-300 font-sans text-[11px]">
                        {activeSelectedWorkstream.acceptanceCriteria.map((ac, i) => (
                          <li key={i} className="flex items-start gap-1.5 leading-snug">
                            <CheckCircle2 size={12} className="text-emerald-400 shrink-0 mt-0.5" />
                            <span>{ac}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="p-8 rounded-2xl bg-slate-900/40 border border-white/10 text-center text-slate-400 text-xs">
                  Select any workstream node from the left to inspect its detailed backlog tasks, prerequisites, and unblocks.
                </div>
              )}
            </div>
          </div>
        </section>
      )}

      {/* --------------------------------------------------------------------- */}
      {/* 5. Functional Ecosystem Map (Modules A through H)                      */}
      {/* --------------------------------------------------------------------- */}
      {activeSection === 'ecosystem' && (
        <section className="space-y-6 pt-2">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/5 pb-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-amber-400">Capability Ecosystem</span>
                <span className="text-slate-600">·</span>
                <span className="text-xs font-mono text-slate-400">Eight Modular Capabilities (A through H)</span>
              </div>
              <h2 className="text-lg font-bold text-white">
                Functional Capability Map & Module Scope
              </h2>
            </div>
            <span className="text-xs font-mono text-slate-400">
              Grouped into operational clusters from data ingestion to commercial UX
            </span>
          </div>

          <div className="space-y-6">
            {moduleClusters.map((cluster, cIdx) => (
              <div key={cIdx} className="space-y-3">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-amber-400" />
                  <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider">{cluster.clusterName}</h3>
                  <span className="text-xs text-slate-400 font-sans">({cluster.clusterDesc})</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {cluster.modules.map((m) => {
                    const Icon = m.icon
                    const isSelected = selectedModuleLetter === m.letter
                    return (
                      <div
                        key={m.letter}
                        onClick={() => setSelectedModuleLetter(isSelected ? null : m.letter)}
                        className={`p-4 rounded-xl border transition-all cursor-pointer flex flex-col justify-between ${
                          isSelected
                            ? 'bg-slate-900 border-amber-500/60 shadow-lg'
                            : 'bg-slate-900/50 border-white/10 hover:border-amber-500/30 hover:bg-slate-900/80'
                        }`}
                      >
                        <div className="space-y-3">
                          <div className="flex items-start justify-between gap-3">
                            <div className="flex items-center gap-2.5">
                              <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
                                <Icon size={18} />
                              </div>
                              <div>
                                <div className="flex items-center gap-2">
                                  <span className="text-xs font-mono font-bold text-amber-400">Module {m.letter}</span>
                                  <span className="text-slate-600">·</span>
                                  <span className="text-[10px] font-mono text-slate-400">{m.targetStage}</span>
                                </div>
                                <h4 className="text-sm font-bold text-white leading-snug">{m.title}</h4>
                              </div>
                            </div>
                            <span className={`text-[9px] font-mono px-2 py-0.5 rounded-full border shrink-0 ${m.badgeClass}`}>
                              {m.status}
                            </span>
                          </div>

                          {/* Scope Comparison Snippet */}
                          <div className="grid grid-cols-2 gap-2 text-[11px] pt-1">
                            <div className="p-2 rounded-lg bg-emerald-950/20 border border-emerald-500/20 space-y-0.5">
                              <span className="text-[10px] font-mono text-emerald-400 font-semibold block">Verified Reality</span>
                              <p className="text-slate-300 font-sans leading-tight line-clamp-2">{m.currentVerified}</p>
                            </div>
                            <div className="p-2 rounded-lg bg-amber-950/20 border border-amber-500/20 space-y-0.5">
                              <span className="text-[10px] font-mono text-amber-400 font-semibold block">Missing / Planned</span>
                              <p className="text-amber-200/80 font-sans leading-tight line-clamp-2">{m.missingWork}</p>
                            </div>
                          </div>
                        </div>

                        <div className="mt-3 pt-2 border-t border-white/5 flex items-center justify-between text-[10px] font-mono">
                          <span className="text-slate-400 truncate max-w-[70%]">Acceptance: {m.acceptanceSummary}</span>
                          <span className="text-amber-400 font-semibold flex items-center gap-0.5">
                            <span>{isSelected ? 'Close' : 'View Scope'}</span>
                            <ChevronDown size={11} className={`transition-transform duration-200 ${isSelected ? 'rotate-180' : ''}`} />
                          </span>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            ))}
          </div>

          {/* Expanded Module Detail Drawer */}
          {activeSelectedModule && (
            <div className="p-5 rounded-2xl bg-slate-900 border border-amber-500/30 space-y-4 shadow-xl animate-fade-in relative">
              <button
                onClick={() => setSelectedModuleLetter(null)}
                className="absolute top-4 right-4 p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white transition-colors"
              >
                <X size={16} />
              </button>

              <div className="flex items-center gap-3 border-b border-white/10 pb-3 pr-8">
                <div className="p-2.5 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/20">
                  <activeSelectedModule.icon size={22} />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-amber-400">Module {activeSelectedModule.letter}</span>
                    <span className="text-slate-600">·</span>
                    <span className="text-xs font-mono text-slate-400">{activeSelectedModule.category}</span>
                  </div>
                  <h3 className="text-lg font-bold text-white">{activeSelectedModule.title}</h3>
                </div>
              </div>

              {/* Full Scope Items */}
              <div className="space-y-2">
                <span className="text-xs font-mono uppercase tracking-wider text-amber-300 font-semibold block">
                  Detailed Functional Scope & Architecture Requirements
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-slate-300 font-sans">
                  {activeSelectedModule.scope.map((item, idx) => (
                    <div key={idx} className="flex items-start gap-1.5 leading-snug">
                      <ChevronRight size={13} className="text-amber-400 shrink-0 mt-0.5" />
                      <span className="text-[11px]">{item}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-white/5 text-xs">
                <div className="p-3 rounded-xl bg-black/40 border border-white/5 space-y-1">
                  <span className="text-[10px] font-mono text-slate-400 uppercase block">Dependencies</span>
                  <span className="text-slate-200 font-sans text-[11px]">{activeSelectedModule.dependencies}</span>
                </div>
                <div className="p-3 rounded-xl bg-black/40 border border-white/5 space-y-1">
                  <span className="text-[10px] font-mono text-emerald-400 uppercase block">Acceptance Criteria</span>
                  <span className="text-emerald-200/90 font-sans text-[11px]">{activeSelectedModule.acceptanceSummary}</span>
                </div>
              </div>
            </div>
          )}
        </section>
      )}

      {/* --------------------------------------------------------------------- */}
      {/* 6. Governance, Research Protocols & Cross-Cutting Principles           */}
      {/* --------------------------------------------------------------------- */}
      {activeSection === 'governance' && (
        <section className="space-y-6 pt-2">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/5 pb-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-purple-400">Architecture Governance</span>
                <span className="text-slate-600">·</span>
                <span className="text-xs font-mono text-slate-400">Protocols & Alignment</span>
              </div>
              <h2 className="text-lg font-bold text-white">
                Technical Governance, Protocols & Alignment Matrix
              </h2>
            </div>

            {/* Sub-tabs */}
            <div className="inline-flex p-1 rounded-xl bg-slate-900 border border-white/10 text-xs font-mono">
              <button
                onClick={() => setActiveGovTab('principles')}
                className={`px-3 py-1 rounded-lg transition-colors ${
                  activeGovTab === 'principles' ? 'bg-purple-500/20 text-purple-300 font-bold' : 'text-slate-400 hover:text-white'
                }`}
              >
                Architectural Principles
              </button>
              <button
                onClick={() => setActiveGovTab('gan_protocol')}
                className={`px-3 py-1 rounded-lg transition-colors ${
                  activeGovTab === 'gan_protocol' ? 'bg-purple-500/20 text-purple-300 font-bold' : 'text-slate-400 hover:text-white'
                }`}
              >
                GAN Research Agenda
              </button>
              <button
                onClick={() => setActiveGovTab('matrix')}
                className={`px-3 py-1 rounded-lg transition-colors ${
                  activeGovTab === 'matrix' ? 'bg-purple-500/20 text-purple-300 font-bold' : 'text-slate-400 hover:text-white'
                }`}
              >
                Alignment Matrix
              </button>
            </div>
          </div>

          {/* Sub-view 1: Cross-Cutting Architectural Principles */}
          {activeGovTab === 'principles' && (
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4 animate-fade-in">
              {/* 1. Model Intelligence & Lifecycle Management */}
              <div className="p-4 rounded-xl bg-black/40 border border-cyan-500/20 space-y-2.5">
                <div className="flex items-center gap-2 text-cyan-400 font-mono font-bold text-xs">
                  <Boxes size={14} />
                  <span>Model Intelligence & Lifecycle Management</span>
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed font-sans">
                  A platform-wide capability governing model operations beyond static weights. Covers five comprehensive lifecycle pillars:
                </p>
                <ul className="space-y-1 text-[11px] text-slate-400 font-sans">
                  <li className="flex items-start gap-1"><ChevronRight size={11} className="text-cyan-400 shrink-0 mt-0.5" /><span><strong>A. Dataset Governance:</strong> Versioning, quality validation, train/test isolation.</span></li>
                  <li className="flex items-start gap-1"><ChevronRight size={11} className="text-cyan-400 shrink-0 mt-0.5" /><span><strong>B. Model Registry:</strong> Artifact tracking, transformer compatibility.</span></li>
                  <li className="flex items-start gap-1"><ChevronRight size={11} className="text-cyan-400 shrink-0 mt-0.5" /><span><strong>C. Monitoring:</strong> Per-family F1, FPR/FNR trends, concept drift.</span></li>
                  <li className="flex items-start gap-1"><ChevronRight size={11} className="text-cyan-400 shrink-0 mt-0.5" /><span><strong>D. Retraining:</strong> Baseline regression tests, mandatory human sign-off.</span></li>
                  <li className="flex items-start gap-1"><ChevronRight size={11} className="text-cyan-400 shrink-0 mt-0.5" /><span><strong>E. Rollouts:</strong> Canary rollouts, automated rollback, audit trails.</span></li>
                </ul>
              </div>

              {/* 2. Platform Security & Tenant Trust */}
              <div className="p-4 rounded-xl bg-black/40 border border-purple-500/20 space-y-2.5">
                <div className="flex items-center gap-2 text-purple-400 font-mono font-bold text-xs">
                  <ShieldCheck size={14} />
                  <span>Platform Security & Tenant Trust</span>
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed font-sans">
                  Strict multi-tenant cryptographic isolation enforced across ten non-negotiable boundaries:
                </p>
                <ul className="space-y-1 text-[11px] text-slate-400 font-sans">
                  <li className="flex items-start gap-1"><ChevronRight size={11} className="text-purple-400 shrink-0 mt-0.5" /><span><strong>1. DB Isolation:</strong> Schema-per-tenant or row-level security.</span></li>
                  <li className="flex items-start gap-1"><ChevronRight size={11} className="text-purple-400 shrink-0 mt-0.5" /><span><strong>2. Storage & Queue:</strong> Isolated evidence buckets & Kafka topics.</span></li>
                  <li className="flex items-start gap-1"><ChevronRight size={11} className="text-purple-400 shrink-0 mt-0.5" /><span><strong>3. API Auth:</strong> Scoped JWT claims checked on every endpoint.</span></li>
                  <li className="flex items-start gap-1"><ChevronRight size={11} className="text-purple-400 shrink-0 mt-0.5" /><span><strong>4. Negative Testing:</strong> Automated cross-tenant penetration test suite.</span></li>
                  <li className="flex items-start gap-1"><ChevronRight size={11} className="text-purple-400 shrink-0 mt-0.5" /><span><strong>5. Secrets:</strong> HashiCorp Vault envelope encryption & key rotation.</span></li>
                </ul>
              </div>

              {/* 3. Performance Target Governance */}
              <div className="p-4 rounded-xl bg-black/40 border border-amber-500/20 space-y-2.5">
                <div className="flex items-center gap-2 text-amber-400 font-mono font-bold text-xs">
                  <Scale size={14} />
                  <span>Performance Target Governance</span>
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed font-sans">
                  Targets are designated as <strong>Provisional Engineering Targets</strong> requiring formal 8-parameter benchmarking:
                </p>
                <ul className="space-y-1 text-[11px] text-slate-400 font-sans">
                  <li className="flex items-start gap-1"><ChevronRight size={11} className="text-amber-400 shrink-0 mt-0.5" /><span>Hardware CPU/RAM specs & workload definition.</span></li>
                  <li className="flex items-start gap-1"><ChevronRight size={11} className="text-amber-400 shrink-0 mt-0.5" /><span>Distinguish model inference latency from end-to-end latency.</span></li>
                  <li className="flex items-start gap-1"><ChevronRight size={11} className="text-amber-400 shrink-0 mt-0.5" /><span>Distinguish event ingestion rate from network wire rate in Gbps.</span></li>
                  <li className="flex items-start gap-1"><ChevronRight size={11} className="text-amber-400 shrink-0 mt-0.5" /><span>p50, p95, p99 percentiles under sustained continuous soak.</span></li>
                </ul>
              </div>

              {/* 4. Cross-Cutting Explainability */}
              <div className="p-4 rounded-xl bg-black/40 border border-emerald-500/20 space-y-2">
                <div className="flex items-center gap-2 text-emerald-400 font-mono font-bold text-xs">
                  <Sliders size={14} />
                  <span>Cross-Cutting Explainability</span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed font-sans">
                  SHAP feature attributions for known threat classifications, reconstruction error decomposition for novel zero-days, 5-term priority score breakdown, and chronological kill-chain incident timelines.
                </p>
              </div>

              {/* 5. Guardrailed Human Approval */}
              <div className="p-4 rounded-xl bg-black/40 border border-red-500/20 space-y-2">
                <div className="flex items-center gap-2 text-red-400 font-mono font-bold text-xs">
                  <Workflow size={14} />
                  <span>Guardrailed Human Approval</span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed font-sans">
                  All active containment, firewall rule updates, endpoint isolation, and detection rule modifications require explicit, authenticated analyst authorization. Autonomous destructive blocking is strictly excluded.
                </p>
              </div>

              {/* 6. Ecosystem Interoperability */}
              <div className="p-4 rounded-xl bg-black/40 border border-blue-500/20 space-y-2">
                <div className="flex items-center gap-2 text-blue-400 font-mono font-bold text-xs">
                  <GitFork size={14} />
                  <span>Open Standards Interoperability</span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed font-sans">
                  Designed for ecosystem coexistence: OCSF/ECS event schemas, STIX/TAXII 2.1 threat intelligence feeds, Sigma/YARA-L detection rules, and OpenAPI 3.1 microservice contracts.
                </p>
              </div>
            </div>
          )}

          {/* Sub-view 2: GAN Research Agenda */}
          {activeGovTab === 'gan_protocol' && (
            <div className="p-6 rounded-2xl bg-gradient-to-br from-purple-950/30 via-slate-900/60 to-black/60 border border-purple-500/20 space-y-5 animate-fade-in">
              <div className="border-b border-purple-500/20 pb-3">
                <span className="text-xs font-mono text-purple-400 font-bold uppercase tracking-wider block">P4 Extension Agenda</span>
                <h3 className="text-base font-bold text-white">
                  Formal GAN / CTGAN Synthetic Traffic & Adversarial Research Methodology
                </h3>
              </div>

              <div className="text-xs text-slate-300 leading-relaxed font-sans space-y-2">
                <p>
                  <strong>Current Repository Reality:</strong> The existing implementation applies two-sided numerical Constrained FGSM, Universal Adversarial Perturbations (UAP), and an empirical DEMGAN manifold drift surrogate. <em>No neural GAN generator exists in the current codebase.</em> DEMGAN in AEGIS is an empirical approximation drifting mutable features toward benign centroids with calibrated Gaussian jitter under strict protocol clamps.
                </p>
                <p className="text-slate-400">
                  Future research will execute a rigorous, controlled comparative evaluation to determine whether deep tabular generative models can synthesize high-fidelity flow records without violating protocol invariants or inflating false alarms.
                </p>
              </div>

              <div className="grid md:grid-cols-3 gap-4 pt-1">
                <div className="p-3.5 rounded-xl bg-black/40 border border-purple-500/20 space-y-1.5 text-xs">
                  <span className="font-mono font-bold text-purple-300 block">Candidate Approaches</span>
                  <ul className="space-y-1 text-slate-400">
                    <li>1. Clean baseline (no augmentation)</li>
                    <li>2. SMOTE (Synthetic Minority Over-sampling)</li>
                    <li>3. ADASYN (Adaptive Synthetic sampling)</li>
                    <li>4. CTGAN (Conditional Tabular GAN)</li>
                    <li>5. WGAN-GP (Wasserstein GAN + GP)</li>
                  </ul>
                </div>

                <div className="p-3.5 rounded-xl bg-black/40 border border-purple-500/20 space-y-1.5 text-xs">
                  <span className="font-mono font-bold text-purple-300 block">Experimental Hygiene</span>
                  <ul className="space-y-1 text-slate-400">
                    <li>• Strict Partitioning: Fit strictly on train split</li>
                    <li>• Zero Test Leakage: Test holdouts untouched</li>
                    <li>• Negative Results: Mandatory disclosure</li>
                    <li>• Statistical Rigour: Paired t-tests & Wilcoxon</li>
                  </ul>
                </div>

                <div className="p-3.5 rounded-xl bg-black/40 border border-purple-500/20 space-y-1.5 text-xs">
                  <span className="font-mono font-bold text-purple-300 block">Research Gate Criteria</span>
                  <p className="text-slate-400 leading-snug">
                    Adopt deep tabular generative models only if they produce measurable, statistically verified gains over simpler augmentation without compromising data quality or privacy.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Sub-view 3: Full Alignment Matrix Table */}
          {activeGovTab === 'matrix' && (
            <div className="glass-card overflow-hidden border border-white/10 animate-fade-in space-y-3 p-4">
              <div className="flex items-center justify-between pb-2 border-b border-white/10">
                <span className="text-xs font-mono font-bold text-slate-300 uppercase">Capability Alignment Matrix (Modules A–H vs Stages 1–6)</span>
                <span className="text-[11px] font-mono text-cyan-400">Verified Technical Traceability</span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-white/10 bg-black/40 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
                      <th className="p-3 pl-4">Module</th>
                      <th className="p-3">Current Verified Reality</th>
                      <th className="p-3">Remaining Scope</th>
                      <th className="p-3">Target Stage</th>
                      <th className="p-3 pr-4">Acceptance Criteria</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5 font-mono">
                    <tr className="hover:bg-white/5 transition-colors">
                      <td className="p-3 pl-4 font-bold text-white">A. Data Ingestion</td>
                      <td className="p-3 text-slate-400">CSV ingestion & synthetic flow presets</td>
                      <td className="p-3 text-slate-300 font-sans">Live NIC capture, PCAP parsing, NetFlow, OCSF</td>
                      <td className="p-3 text-cyan-400">Stage 3 & 4</td>
                      <td className="p-3 pr-4 text-emerald-400 font-sans">≥ 10k events/sec sustained ingestion</td>
                    </tr>
                    <tr className="hover:bg-white/5 transition-colors bg-emerald-500/5">
                      <td className="p-3 pl-4 font-bold text-white">B. Threat Detection</td>
                      <td className="p-3 text-emerald-400">P1 MLPRegressor bottleneck reconstruction + XGBoost, P2 Encrypted Flow XGBoost, P4 Retrained Hardened XGBoost</td>
                      <td className="p-3 text-slate-300 font-sans">Model lifecycle registry, drift, GAN research, UEBA, Sigma</td>
                      <td className="p-3 text-emerald-400">Stage 2 & 3</td>
                      <td className="p-3 pr-4 text-emerald-400 font-sans">Sub-5ms model inference latency per flow</td>
                    </tr>
                    <tr className="hover:bg-white/5 transition-colors bg-emerald-500/5">
                      <td className="p-3 pl-4 font-bold text-white">C. Alert Intelligence</td>
                      <td className="p-3 text-emerald-400">P3 5-factor composite priority with Critical, Review, Auto-log tiers</td>
                      <td className="p-3 text-slate-300 font-sans">Cross-sensor correlation, deduplication, CMDB sync</td>
                      <td className="p-3 text-emerald-400">Stage 2 & 3</td>
                      <td className="p-3 pr-4 text-emerald-400 font-sans">≥ 60% alert noise reduction into incidents</td>
                    </tr>
                    <tr className="hover:bg-white/5 transition-colors">
                      <td className="p-3 pl-4 font-bold text-white">D. Incident Management</td>
                      <td className="p-3 text-slate-400">Triage queue & SHAP feature breakdown</td>
                      <td className="p-3 text-slate-300 font-sans">Incident grouping, attack timelines, MITRE ATT&CK mapping</td>
                      <td className="p-3 text-cyan-400">Stage 3 & 4</td>
                      <td className="p-3 pr-4 text-emerald-400 font-sans">Kill-chain visualization; exportable compliance reports</td>
                    </tr>
                    <tr className="hover:bg-white/5 transition-colors">
                      <td className="p-3 pl-4 font-bold text-white">E. Response Automation</td>
                      <td className="p-3 text-slate-400">Triage recommendations & manual preset replay</td>
                      <td className="p-3 text-slate-300 font-sans">Response playbooks, ticketing dispatch, SOAR connectors</td>
                      <td className="p-3 text-cyan-400">Stage 3 & 4</td>
                      <td className="p-3 pr-4 text-emerald-400 font-sans">Zero autonomous destructive actions; 100% human sign-off</td>
                    </tr>
                    <tr className="hover:bg-white/5 transition-colors">
                      <td className="p-3 pl-4 font-bold text-white">F. SaaS Governance</td>
                      <td className="p-3 text-slate-400">Health liveness check & DB connection telemetry</td>
                      <td className="p-3 text-slate-300 font-sans">10 isolation boundaries, negative auth testing, SSO/MFA, RBAC, quotas</td>
                      <td className="p-3 text-cyan-400">Stage 1 & 4</td>
                      <td className="p-3 pr-4 text-emerald-400 font-sans">99.9% availability; zero cross-tenant leakage; RTO ≤ 15m</td>
                    </tr>
                    <tr className="hover:bg-white/5 transition-colors bg-indigo-500/5">
                      <td className="p-3 pl-4 font-bold text-white">G. Future AI Capabilities</td>
                      <td className="p-3 text-slate-400">SHAP tree explanations & reconstruction error shares</td>
                      <td className="p-3 text-slate-300 font-sans">AI analyst chatbot, text-to-query, incident summarization</td>
                      <td className="p-3 text-indigo-400">Stage 5</td>
                      <td className="p-3 pr-4 text-indigo-300 font-sans">≥ 99% prompt-injection defense rate; 100% human sign-off</td>
                    </tr>
                    <tr className="hover:bg-white/5 transition-colors bg-purple-500/5">
                      <td className="p-3 pl-4 font-bold text-white">H. Future Product Experience</td>
                      <td className="p-3 text-slate-400">React + Vite + Tailwind SOC dashboard v2.4</td>
                      <td className="p-3 text-slate-300 font-sans">Tenant-specific dashboards, attack graphs, forensic workbench</td>
                      <td className="p-3 text-purple-400">Stage 6</td>
                      <td className="p-3 pr-4 text-purple-300 font-sans">≥ 3 authorized enterprise pilots; ≥ 40% triage reduction</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </section>
      )}
    </div>
  )
}
